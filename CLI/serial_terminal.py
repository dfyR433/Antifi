from datetime import datetime, timezone
import argparse
import serial
import threading
import time
import os
import sys
import codecs

PRE_PRINT_TIME = 0.5   # seconds to print immediately after sniff command
POST_STOP_GRACE = 0.8    # small time to allow trailing bytes to arrive before saving
DEFAULT_BAUD = 921600
PARTIAL_FLUSH_TIMEOUT = 0.18  # seconds to flush a partial line if no newline arrives

def safe_print(lock, text="", end="\n"):
    """Thread-safe printing used for status and final messages."""
    with lock:
        sys.stdout.write(text + ("" if end == "" else end))
        sys.stdout.flush()

def reader_loop(ser, stop_event, capture_event, capture_lock, capture_chunks, print_lock):
    """
    Read from serial continuously.
    - When capture_event is set: append raw chunks to capture_chunks (silent).
    - Otherwise: decode incrementally to UTF-8, normalize CR/LF to LF, buffer partial lines,
      and print only complete lines immediately. Flush partial line if no newline arrives
      for PARTIAL_FLUSH_TIMEOUT to keep responsivity.
    """
    decoder = codecs.getincrementaldecoder('utf-8')()
    line_buffer = ""            # holds decoded text not yet printed (maybe partial)
    last_partial_time = 0.0

    while not stop_event.is_set():
        try:
            data = ser.read(4096)
        except Exception:
            break
        if not data:
            # if there's an outstanding partial we may want to flush after timeout
            if line_buffer and (time.time() - last_partial_time) >= PARTIAL_FLUSH_TIMEOUT and not capture_event.is_set():
                with print_lock:
                    sys.stdout.write(line_buffer)
                    sys.stdout.flush()
                line_buffer = ""
            time.sleep(0.001)
            continue

        if capture_event.is_set():
            # silent buffering of raw bytes
            with capture_lock:
                capture_chunks.append(data)
            # while capturing, don't process decoded printing at all
            continue

        # decode bytes incrementally (handles UTF-8 splits across chunks)
        try:
            text = decoder.decode(data)
        except Exception:
            # fallback: replace errors
            text = data.decode('utf-8', errors='replace')

        # normalize CRLF and CR to LF
        if "\r" in text:
            text = text.replace("\r\n", "\n").replace("\r", "\n")

        # append to line buffer
        line_buffer += text
        last_partial_time = time.time()

        # print full lines if present
        while True:
            if "\n" in line_buffer:
                line, line_buffer = line_buffer.split("\n", 1)
                with print_lock:
                    sys.stdout.write(line + "\n")
                    sys.stdout.flush()
                last_partial_time = time.time()
            else:
                # no full line left
                break

        # flush partial line if no newline for a short time (keep responsive)
        if line_buffer and (time.time() - last_partial_time) >= PARTIAL_FLUSH_TIMEOUT:
            with print_lock:
                sys.stdout.write(line_buffer)
                sys.stdout.flush()
            line_buffer = ""
            last_partial_time = time.time()

    # thread exiting

def save_capture_as_pcapng(outdir, channel_label, index, capture_chunks):
    """
    Save buffered raw bytes as .pcapng (device already outputs valid pcapng bytes).
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    ch_label = f"_ch{channel_label}" if channel_label and channel_label.lower() != "all" else ""
    filename = f"capture{ch_label}_{ts}_{index}.pcapng"
    filepath = os.path.join(outdir, filename)
    total = 0
    with open(filepath, "wb") as f:
        for chunk in capture_chunks:
            f.write(chunk)
            total += len(chunk)
    return filepath, total

def main():
    parser = argparse.ArgumentParser(description="Serial terminal for raw pcapng frames (clean printing)")
    parser.add_argument("-p", "--port", required=True, help="Serial port (e.g. /dev/ttyUSB0 or COM5)")
    parser.add_argument("-b", "--baud", type=int, default=DEFAULT_BAUD, help=f"Baud rate (default {DEFAULT_BAUD})")
    parser.add_argument("--outdir", default=".", help="Directory to save captures (default current dir)")
    args = parser.parse_args()

    try:
        ser = serial.Serial(args.port, args.baud, timeout=0.01)
    except Exception as e:
        print(f"ERROR: failed to open {args.port}: {e}")
        return

    os.makedirs(args.outdir, exist_ok=True)

    stop_event = threading.Event()
    capture_event = threading.Event()
    capture_lock = threading.Lock()
    capture_chunks = []
    capture_index = 0
    capture_channel = None
    print_lock = threading.Lock()

    reader_thread = threading.Thread(
        target=reader_loop,
        args=(ser, stop_event, capture_event, capture_lock, capture_chunks, print_lock),
        daemon=True
    )
    reader_thread.start()

    safe_print(print_lock, f"Connected to {args.port} @ {args.baud}")

    try:
        while True:
            try:
                line = input()   # visible input, no prompt
            except EOFError:
                break

            if not line:
                continue

            # send typed command to device
            try:
                ser.write((line + "\r\n").encode())
            except Exception as e:
                safe_print(print_lock, f"[ERROR] write failed: {e}")
                # continue

            cmd = line.strip()
            if cmd.lower().startswith("sniff -c"):
                # sniff: print brief, then silently buffer
                parts = cmd.split()
                capture_channel = parts[2] if len(parts) >= 3 else None

                # allow printing for a short time so user sees immediate output
                time.sleep(PRE_PRINT_TIME)

                # start silent capture
                with capture_lock:
                    capture_chunks.clear()
                capture_event.set()
                safe_print(print_lock, "[CAPTURING] silently buffering device bytes until you type 'stop'")

                # wait for user to type 'stop'
                while True:
                    try:
                        subline = input()
                    except EOFError:
                        subline = ""

                    if not subline:
                        continue

                    # send sub-command to device
                    try:
                        ser.write((subline + "\r\n").encode())
                    except Exception:
                        pass

                    if subline.strip().lower() == "stop":
                        # still silent: allow a tiny grace period to collect trailing bytes
                        time.sleep(POST_STOP_GRACE)
                        capture_event.clear()
                        with capture_lock:
                            saved_chunks = list(capture_chunks)
                        try:
                            filepath, total_bytes = save_capture_as_pcapng(args.outdir, capture_channel, capture_index, saved_chunks)
                            safe_print(print_lock, f"\n[CAPTURE SAVED] {filepath} ({total_bytes} bytes)\n", end="")
                        except Exception as e:
                            safe_print(print_lock, f"\n[ERROR] failed to save capture: {e}\n", end="")
                        capture_index += 1
                        with capture_lock:
                            capture_chunks.clear()
                        capture_channel = None
                        break
                    # otherwise continue capturing silently

    except KeyboardInterrupt:
        safe_print(print_lock, "\nInterrupted. Exiting...")
    finally:
        stop_event.set()
        reader_thread.join(timeout=0.5)
        try:
            ser.close()
        except Exception:
            pass
        safe_print(print_lock, "Closed.")

if __name__ == "__main__":
    main()
