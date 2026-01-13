#include "beacon.h"

const char* SSID_LIST[] = {
  "FreeWiFi", "PublicWiFi", "CoffeeShop", "AirportWiFi", "HotelGuest",
  "Starbucks", "McDonalds", "Library", "MallWiFi", "TrainStation",
  "BusWiFi", "TaxiWiFi", "Cafe", "Restaurant", "ShopWiFi",
  "GuestNetwork", "VisitorWiFi", "Conference", "MeetingRoom", "Lobby",
  "Reception", "Office", "Store", "Museum", "Park",
  "CityWiFi", "Municipal", "PublicAccess", "FreeInternet", "OpenNetwork",
  "TestNetwork", "Demo", "Example", "Sample", "Temporary",
  "Mobile", "Hotspot", "Portal", "Captive", "Login",
  "SecureWiFi", "Private", "Staff", "Employee", "Admin",
  "Corporate", "Business", "Enterprise", "Company", "Work",
  "Home", "Family", "Personal", "MyWiFi", "Router",
  "Modem", "Gateway", "AccessPoint", "Wireless", "Network",
  "Internet", "Broadband", "DSL", "Cable", "Fiber",
  "5G", "LTE", "MobileHotspot", "Tethering", "Phone",
  "AndroidAP", "iPhone", "iPad", "Tablet", "Laptop",
  "Desktop", "PC", "Mac", "Linux", "Windows",
  "Chromebook", "SmartTV", "Gaming", "Console", "Xbox",
  "PlayStation", "Nintendo", "Switch", "VR", "IoT",
  "SmartHome", "Camera", "Speaker", "Light", "Thermostat",
  "Security", "Alarm", "Sensor", "Device", "Gadget",
  "Tech", "Electronic", "Digital", "Smart", "Connected",
  "Future", "NextGen", "Modern", "Advanced", "Premium",
  "Basic", "Standard", "Economy", "Budget", "Free",
  "Unlimited", "Fast", "Quick", "Speed", "Turbo",
  "Boost", "Extreme", "Ultra", "Max", "Pro",
  "Plus", "Extra", "Super", "Mega", "Giga",
  "Tera", "Peta", "Exa", "Zetta", "Yotta",
  "Alpha", "Beta", "Gamma", "Delta", "Epsilon",
  "Zeta", "Eta", "Theta", "Iota", "Kappa",
  "Lambda", "Mu", "Nu", "Xi", "Omicron",
  "Pi", "Rho", "Sigma", "Tau", "Upsilon",
  "Phi", "Chi", "Psi", "Omega", "Infinity",

  // Corporate Networks (100)
  "CORP_WIFI", "OFFICE_SECURE", "BUSINESS_NET", "COMPANY_GUEST",
  "ENTERPRISE", "INTRANET", "VPN_ACCESS", "SERVER_ROOM",
  "CORPORATE", "OFFICE_WIFI", "BUSINESS_GUEST", "STAFF_NETWORK",
  "EXECUTIVE", "CONFERENCE", "MEETING_ROOM", "HR_DEPARTMENT",
  "IT_DEPARTMENT", "ADMIN_NET", "SERVER_FARM", "DATA_CENTER",
  "BACKUP_NET", "STORAGE_NET", "CLOUD_ACCESS", "REMOTE_ACCESS",
  "BRANCH_OFFICE", "HQ_NETWORK", "CORP_SECURE", "WIRELESS_CORP",
  "CORP_ACCESS", "OFFICE_NET", "BUSINESS_ACCESS", "COMPANY_WIFI",
  "CORP_INTRANET", "OFFICE_GUEST", "BUSINESS_WIFI", "COMPANY_NET",
  "CORP_GUEST", "OFFICE_NETWORK", "BUSINESS_ACCESS", "COMPANY_ACCESS",
  "CORP_WIRELESS", "OFFICE_ACCESS", "BUSINESS_NETWORK", "COMPANY_WIRELESS",
  "CORP_ONLINE", "OFFICE_ONLINE", "BUSINESS_ONLINE", "COMPANY_ONLINE",
  "CORP_CONNECT", "OFFICE_CONNECT", "BUSINESS_CONNECT", "COMPANY_CONNECT",
  "CORP_SYSTEM", "OFFICE_SYSTEM", "BUSINESS_SYSTEM", "COMPANY_SYSTEM",
  "CORP_TECH", "OFFICE_TECH", "BUSINESS_TECH", "COMPANY_TECH",
  "CORP_IT", "OFFICE_IT", "BUSINESS_IT", "COMPANY_IT",
  "CORP_SECURITY", "OFFICE_SECURITY", "BUSINESS_SECURITY", "COMPANY_SECURITY",
  "CORP_VPN", "OFFICE_VPN", "BUSINESS_VPN", "COMPANY_VPN",
  "CORP_REMOTE", "OFFICE_REMOTE", "BUSINESS_REMOTE", "COMPANY_REMOTE",
  "CORP_CLOUD", "OFFICE_CLOUD", "BUSINESS_CLOUD", "COMPANY_CLOUD",
  "CORP_DATA", "OFFICE_DATA", "BUSINESS_DATA", "COMPANY_DATA",
  "CORP_SERVER", "OFFICE_SERVER", "BUSINESS_SERVER", "COMPANY_SERVER",
  "CORP_NETWORK", "OFFICE_NETWORK", "BUSINESS_NETWORK", "COMPANY_NETWORK",
  "CORP_WLAN", "OFFICE_WLAN", "BUSINESS_WLAN", "COMPANY_WLAN",
  "CORP_AP", "OFFICE_AP", "BUSINESS_AP", "COMPANY_AP",

  // Government/Military (80)
  "GOV_SECURE", "MILITARY_NET", "POLICE_WIFI", "FIRE_DEPT",
  "EMERGENCY", "RESCUE_TEAM", "SECURITY_NET", "SURVEILLANCE",
  "GOV_WIFI", "PUBLIC_SAFETY", "LAW_ENFORCEMENT", "DEFENSE_NET",
  "INTELLIGENCE", "AGENCY_NET", "DEPARTMENT", "FEDERAL",
  "STATE_NET", "CITY_WIFI", "MUNICIPAL", "GOV_GUEST",
  "GOV_ACCESS", "MILITARY_ACCESS", "POLICE_NET", "FIRE_NET",
  "EMERGENCY_NET", "RESCUE_NET", "SECURITY_ACCESS", "SURVEILLANCE_NET",
  "GOV_PUBLIC", "MILITARY_PUBLIC", "POLICE_PUBLIC", "FIRE_PUBLIC",
  "EMERGENCY_PUBLIC", "RESCUE_PUBLIC", "SECURITY_PUBLIC", "SURVEILLANCE_PUBLIC",
  "GOV_PRIVATE", "MILITARY_PRIVATE", "POLICE_PRIVATE", "FIRE_PRIVATE",
  "EMERGENCY_PRIVATE", "RESCUE_PRIVATE", "SECURITY_PRIVATE", "SURVEILLANCE_PRIVATE",
  "GOV_SECRET", "MILITARY_SECRET", "POLICE_SECRET", "FIRE_SECRET",
  "EMERGENCY_SECRET", "RESCUE_SECRET", "SECURITY_SECRET", "SURVEILLANCE_SECRET",
  "GOV_CLASSIFIED", "MILITARY_CLASSIFIED", "POLICE_CLASSIFIED", "FIRE_CLASSIFIED",
  "EMERGENCY_CLASSIFIED", "RESCUE_CLASSIFIED", "SECURITY_CLASSIFIED", "SURVEILLANCE_CLASSIFIED",
  "GOV_TOP_SECRET", "MILITARY_TOP_SECRET", "POLICE_TOP_SECRET", "FIRE_TOP_SECRET",
  "EMERGENCY_TOP_SECRET", "RESCUE_TOP_SECRET", "SECURITY_TOP_SECRET", "SURVEILLANCE_TOP_SECRET",
  "GOV_RESTRICTED", "MILITARY_RESTRICTED", "POLICE_RESTRICTED", "FIRE_RESTRICTED",
  "EMERGENCY_RESTRICTED", "RESCUE_RESTRICTED", "SECURITY_RESTRICTED", "SURVEILLANCE_RESTRICTED",

  // Infrastructure (80)
  "POWER_GRID", "WATER_PLANT", "TRAFFIC_CTRL", "AIRPORT_CTRL",
  "RAIL_CONTROL", "BRIDGE_MGMT", "TUNNEL_NET", "HARBOR_CTRL",
  "UTILITIES", "GRID_CONTROL", "SCADA_NET", "INDUSTRIAL",
  "MANUFACTURING", "FACTORY_NET", "PLANT_WIFI", "CONTROL_NET",
  "TRANSPORT", "LOGISTICS", "SUPPLY_CHAIN", "DISTRIBUTION",
  "POWER_NET", "WATER_NET", "TRAFFIC_NET", "AIRPORT_NET",
  "RAIL_NET", "BRIDGE_NET", "TUNNEL_WIFI", "HARBOR_NET",
  "UTILITY_NET", "GRID_WIFI", "SCADA_WIFI", "INDUSTRY_NET",
  "FACTORY_WIFI", "PLANT_NET", "CONTROL_WIFI", "TRANSPORT_NET",
  "LOGISTICS_NET", "SUPPLY_NET", "DISTRIBUTION_NET", "POWER_ACCESS",
  "WATER_ACCESS", "TRAFFIC_ACCESS", "AIRPORT_ACCESS", "RAIL_ACCESS",
  "BRIDGE_ACCESS", "TUNNEL_ACCESS", "HARBOR_ACCESS", "UTILITY_ACCESS",
  "GRID_ACCESS", "SCADA_ACCESS", "INDUSTRY_ACCESS", "FACTORY_ACCESS",
  "PLANT_ACCESS", "CONTROL_ACCESS", "TRANSPORT_ACCESS", "LOGISTICS_ACCESS",
  "SUPPLY_ACCESS", "DISTRIBUTION_ACCESS", "POWER_SECURE", "WATER_SECURE",
  "TRAFFIC_SECURE", "AIRPORT_SECURE", "RAIL_SECURE", "BRIDGE_SECURE",
  "TUNNEL_SECURE", "HARBOR_SECURE", "UTILITY_SECURE", "GRID_SECURE",
  "SCADA_SECURE", "INDUSTRY_SECURE", "FACTORY_SECURE", "PLANT_SECURE",
  "CONTROL_SECURE", "TRANSPORT_SECURE", "LOGISTICS_SECURE", "SUPPLY_SECURE",
  "DISTRIBUTION_SECURE", "POWER_CONTROL", "WATER_CONTROL", "TRAFFIC_CONTROL",

  // Financial (80)
  "BANK_SECURE", "ATM_NETWORK", "TRADING_FLOOR", "STOCK_EXCHANGE",
  "CREDIT_UNION", "PAYMENT_NET", "TRANSACTION", "CLEARING_HOUSE",
  "BANK_WIFI", "FINANCE_DEPT", "ACCOUNTING", "AUDIT_NET",
  "TRANSFER_NET", "SWIFT_ACCESS", "WIRE_ROOM", "VAULT_NET",
  "TELLER_NET", "BRANCH_NET", "ATM_BACKEND", "CARD_NETWORK",
  "BANK_ACCESS", "ATM_ACCESS", "TRADING_ACCESS", "STOCK_ACCESS",
  "CREDIT_ACCESS", "PAYMENT_ACCESS", "TRANSACTION_ACCESS", "CLEARING_ACCESS",
  "FINANCE_ACCESS", "ACCOUNTING_ACCESS", "AUDIT_ACCESS", "TRANSFER_ACCESS",
  "SWIFT_NET", "WIRE_NET", "VAULT_ACCESS", "TELLER_ACCESS",
  "BRANCH_ACCESS", "ATM_SYSTEM", "CARD_SYSTEM", "BANK_SYSTEM",
  "ATM_SYSTEM", "TRADING_SYSTEM", "STOCK_SYSTEM", "CREDIT_SYSTEM",
  "PAYMENT_SYSTEM", "TRANSACTION_SYSTEM", "CLEARING_SYSTEM", "FINANCE_SYSTEM",
  "ACCOUNTING_SYSTEM", "AUDIT_SYSTEM", "TRANSFER_SYSTEM", "SWIFT_SYSTEM",
  "WIRE_SYSTEM", "VAULT_SYSTEM", "TELLER_SYSTEM", "BRANCH_SYSTEM",
  "ATM_NET", "TRADING_NET", "STOCK_NET", "CREDIT_NET",
  "PAYMENT_NET", "TRANSACTION_NET", "CLEARING_NET", "FINANCE_NET",
  "ACCOUNTING_NET", "AUDIT_NET", "TRANSFER_NET", "SWIFT_NET",
  "WIRE_NET", "VAULT_NET", "TELLER_NET", "BRANCH_NET",
  "ATM_WIFI", "TRADING_WIFI", "STOCK_WIFI", "CREDIT_WIFI",
  "PAYMENT_WIFI", "TRANSACTION_WIFI", "CLEARING_WIFI", "FINANCE_WIFI",

  // Common WiFi Names (100)
  "linksys", "netgear", "dlink", "tplink", "asus",
  "belkin", "cisco", "aruba", "ubiquiti", "meraki",
  "ruckus", "extreme", "juniper", "paloalto", "fortinet",
  "sonicwall", "checkpoint", "sophos", "watchguard", "barracuda",
  "zyxel", "buffalo", "trendnet", "actiontec", "motorola",
  "technicolor", "sagemcom", "huawei", "zte", "nokia",
  "ericsson", "samsung", "lg", "apple", "google",
  "amazon", "facebook", "microsoft", "ibm", "dell",
  "hp", "lenovo", "acer", "toshiba", "fujitsu",
  "panasonic", "sharp", "sanyo", "philips", "siemens",
  "bosch", "ge", "honeywell", "schneider", "abb",
  "emerson", "rockwell", "yokogawa", "mitsubishi", "omron",
  "festo", "sick", "keyence", "cognex", "banner",
  "balluff", "ifm", "pepperl", "turck", "weidmuller",
  "phoenix", "wago", "beckhoff", "b&r", "siemens_s7",
  "allenbradley", "rockwell_ab", "modicon", "schneider_electric", "abb_control",
  "yaskawa", "fanuc", "kuka", "abb_robot", "motoman",
  "universal", "staubli", "comau", "kawasaki", "nachirobotics",
  "denso", "epson", "yamaha", "hirata", "adept",

  // Generic WiFi Names (200)
  "wireless", "wifi", "network", "internet", "broadband",
  "router", "modem", "gateway", "accesspoint", "hotspot",
  "connection", "connect", "online", "web", "net",
  "lan", "wlan", "wan", "vlan", "vpn",
  "dhcp", "dns", "nat", "firewall", "proxy",
  "switch", "hub", "bridge", "repeater", "extender",
  "booster", "amplifier", "antenna", "receiver", "transmitter",
  "transceiver", "radio", "wire", "cable", "fiber",
  "copper", "ethernet", "cat5", "cat6", "cat7",
  "rj45", "usb", "hdmi", "displayport", "thunderbolt",
  "bluetooth", "zigbee", "z-wave", "lora", "sigfox",
  "nb-iot", "lte-m", "5g", "4g", "3g",
  "2g", "gsm", "cdma", "wcdma", "td-scdma",
  "wimax", "wifi6", "wifi6e", "wifi7", "80211",
  "80211a", "80211b", "80211g", "80211n", "80211ac",
  "80211ax", "80211be", "ieee", "iso", "ansi",
  "itu", "etsi", "fcc", "ce", "ul",
  "csa", "vde", "tuv", "demko", "semko",
  "nemko", "fimko", "ov", "kema", "sei",
  "ccc", "kc", "pse", "tick", "c-tick",
  "bsmi", "ncc", "ida", "imda", "mcm",
  "srrc", "mic", "kc", "nk", "vcci",
  "bsmi", "ccc", "ce", "fcc", "ul",
  "csa", "tuv", "vde", "demko", "semko",
  "nemko", "fimko", "ov", "kema", "sei",
  "ccc", "kc", "pse", "tick", "c-tick",
  "bsmi", "ncc", "ida", "imda", "mcm",
  "srrc", "mic", "kc", "nk", "vcci",

  // Tech Company WiFi (100)
  "google_guest", "microsoft_wifi", "apple_store", "amazon_locker", "facebook_campus",
  "twitter_hq", "linkedin_office", "instagram_studio", "whatsapp_lab", "tiktok_center",
  "youtube_studio", "netflix_theater", "spotify_radio", "discord_server", "slack_channel",
  "zoom_meeting", "teams_call", "skype_chat", "facetime_video", "duo_call",
  "meet_google", "webex_cisco", "bluejeans", "gotomeeting", "joinme",
  "teamviewer", "anydesk", "logmein", "splashtop", "vnc",
  "rdp", "ssh", "ftp", "sftp", "scp",
  "http", "https", "ssl", "tls", "dtls",
  "ipsec", "ike", "ikev2", "l2tp", "pptp",
  "openvpn", "wireguard", "zerotier", "tailscale", "openconnect",
  "anyconnect", "globalprotect", "pulse", "forticlient", "sonicwall_netextender",

  // Hotel Chains (50)
  "Marriott_Guest", "Hilton_WiFi", "Hyatt_Connect", "Sheraton_Free", "InterContinental",
  "Westin_Hotspot", "RitzCarlton", "FourSeasons", "MandarinOriental", "StRegis",
  "W_Hotels", "JW_Marriott", "Renaissance", "Courtyard", "ResidenceInn",
  "Fairfield", "SpringHill", "TownePlace", "Element", "Aloft",
  "Moxy", "AC_Hotel", "Edition", "Luxury", "Boutique",
  "HolidayInn", "CrownPlaza", "Indigo", "Staybridge", "Candlewood",
  "BestWestern", "Radisson", "CountryInn", "ParkInn", "ParkPlaza",
  "Motel6", "Super8", "DaysInn", "Travelodge", "HowardJohnson",
  "Ramada", "Wyndham", "LaQuinta", "RedRoof", "EconoLodge",
  "ComfortInn", "QualityInn", "SleepInn", "Clarion", "MainStay",

  // Airline WiFi (30)
  "DeltaWiFi", "AmericanAirlines", "United_WiFi", "Southwest", "JetBlue",
  "Alaska_Airlines", "Spirit", "Frontier", "Allegiant", "Hawaiian",
  "BritishAirways", "Lufthansa", "AirFrance", "KLM", "Emirates",
  "Qatar", "Singapore", "Cathay", "ANA", "JAL",
  "Qantas", "Virgin", "Ryanair", "EasyJet", "Wizz",
  "Norwegian", "Finnair", "SAS", "TAP", "Turkish",

  // Coffee Shops & Fast Food (50)
  "Starbucks_Guest", "McDonalds_FreeWiFi", "BurgerKing_WiFi", "Wendys", "TacoBell",
  "KFC_WiFi", "Subway", "PizzaHut", "Dominos", "PapaJohns",
  "DunkinDonuts", "KrispyKreme", "TimHortons", "Caribou", "Peets",
  "CoffeeBean", "Teavana", "Costa", "Pret", "Gregs",
  "Panera", "Chipotle", "Qdoba", "Moe's", "BajaFresh",
  "InNOut", "ShakeShack", "FiveGuys", "Whataburger", "Culvers",
  "Sonic", "Arbys", "JackInTheBox", "WhiteCastle", "RaisingCanes",
  "ChickfilA", "Popeyes", "Krystals", "Hardees", "CarlsJr",
  "Bojangles", "Churchs", "LongJohnSilvers", "CaptainDs", "RedLobster",
  "OliveGarden", "Applebee's", "Chili's", "Outback", "TexasRoadhouse",

  // Retail Stores (50)
  "Walmart_WiFi", "Target_Guest", "Costco", "BestBuy", "HomeDepot",
  "Lowes", "Walgreens", "CVS", "RiteAid", "Kroger",
  "Safeway", "Albertsons", "Publix", "WholeFoods", "TraderJoes",
  "Aldi", "Lidl", "DollarGeneral", "FamilyDollar", "DollarTree",
  "7Eleven", "CircleK", "Shell", "BP", "Exxon",
  "Chevron", "Texaco", "Arco", "Mobil", "Sunoco",
  "Gulf", "Citgo", "Valero", "Marathon", "Phillips66",
  "Caseys", "KwikTrip", "Sheetz", "Wawa", "Buc-ee's",
  "Love's", "Pilot", "FlyingJ", "TravelCenters", "TA",
  "Petro", "Roady's", "RoadRanger", "USA", "SuperAmerica",

  // Educational (50)
  "University_WiFi", "College_Guest", "Campus", "Dorm", "Library",
  "Student_Center", "Cafeteria", "Gym", "Stadium", "Auditorium",
  "Lecture_Hall", "Lab", "Research", "Science", "Engineering",
  "Medical", "Law", "Business", "Arts", "Humanities",
  "Social_Sciences", "Education", "Nursing", "Pharmacy", "Dental",
  "Veterinary", "Agriculture", "Environmental", "Computer", "Information",
  "Technology", "Math", "Physics", "Chemistry", "Biology",
  "Geology", "Astronomy", "Meteorology", "Oceanography", "Psychology",
  "Sociology", "Anthropology", "Economics", "Political", "History",
  "Philosophy", "Religion", "Languages", "Literature", "Music",

  // Hospitals & Healthcare (30)
  "Hospital_Guest", "Clinic_WiFi", "Doctor_Office", "Dental_Clinic", "Vet_Clinic",
  "Pharmacy", "Lab_Results", "Medical_Records", "Patient_Portal", "Telehealth",
  "Emergency", "ICU", "OR", "Radiology", "MRI",
  "CT_Scan", "Xray", "Ultrasound", "EKG", "EEG",
  "Blood_Lab", "Urine_Lab", "Tissue_Lab", "Genetics", "Pathology",
  "Oncology", "Cardiology", "Neurology", "Orthopedics", "Pediatrics",

  // Smart Home Devices (50)
  "Nest", "Ring", "Arlo", "Blink", "Wyze",
  "Eufy", "SimpliSafe", "ADT", "Vivint", "Frontpoint",
  "Abode", "Cove", "Kangaroo", "Google_Nest", "Amazon_Ring",
  "Apple_HomeKit", "Samsung_SmartThings", "Philips_Hue", "LIFX", "TP-Link_Kasa",
  "Wemo", "Meross", "Gosund", "Treatlife", "Sonoff",
  "Shelly", "Aqara", "Xiaomi", "Yeelight", "Tuya",
  "SmartLife", "Echo", "Google_Home", "HomePod", "Sonos",
  "Bose", "JBL", "Harmon_Kardon", "Bang_Olufsen", "Denon",
  "Marantz", "Yamaha", "Onkyo", "Pioneer", "Sony",
  "LG_Smart", "Samsung_TV", "Vizio", "TCL", "Hisense",

  // Gaming (30)
  "Xbox_Live", "PlayStation_Network", "Nintendo", "Steam", "Epic",
  "Origin", "Ubisoft", "EA", "Activision", "Blizzard",
  "Valve", "Riot", "Tencent", "Nexon", "NCSoft",
  "SquareEnix", "Capcom", "Bandai", "Sega", "Konami",
  "Microsoft_Gaming", "Sony_Gaming", "Nintendo_Gaming", "PC_Gaming", "Mobile_Gaming",
  "VR_Gaming", "AR_Gaming", "Cloud_Gaming", "Streaming", "Esports",

  // Transportation (30)
  "Uber", "Lyft", "Taxi", "Bus", "Train",
  "Subway", "Metro", "Tram", "LightRail", "Monorail",
  "Ferry", "Boat", "Ship", "Yacht", "Cruise",
  "Airplane", "Helicopter", "Drone", "EV_Charger", "Tesla",
  "ChargePoint", "EVgo", "ElectrifyAmerica", "Blink_Charging", "SemaConnect",
  "Greenlots", "Volta", "Tesla_Destination", "Tesla_Supercharger", "J1772",

  // Cities & Locations (50)
  "NewYork_WiFi", "LA_Free", "Chicago_Guest", "Houston", "Phoenix",
  "Philadelphia", "SanAntonio", "SanDiego", "Dallas", "SanJose",
  "Austin", "Jacksonville", "FortWorth", "Columbus", "Charlotte",
  "SanFrancisco", "Indianapolis", "Seattle", "Denver", "Washington",
  "Boston", "ElPaso", "Nashville", "Detroit", "OklahomaCity",
  "Portland", "LasVegas", "Memphis", "Louisville", "Baltimore",
  "Milwaukee", "Albuquerque", "Tucson", "Fresno", "Sacramento",
  "KansasCity", "LongBeach", "Mesa", "Atlanta", "ColoradoSprings",
  "Raleigh", "Miami", "VirginiaBeach", "Omaha", "Oakland",
  "Minneapolis", "Tulsa", "Wichita", "NewOrleans", "Arlington",

  // Generic Numbered (100) - Last batch to reach 1000+
  "WiFi_001", "WiFi_002", "WiFi_003", "WiFi_004", "WiFi_005",
  "WiFi_006", "WiFi_007", "WiFi_008", "WiFi_009", "WiFi_010",
  "Network_001", "Network_002", "Network_003", "Network_004", "Network_005",
  "Network_006", "Network_007", "Network_008", "Network_009", "Network_010",
  "AP_001", "AP_002", "AP_003", "AP_004", "AP_005",
  "AP_006", "AP_007", "AP_008", "AP_009", "AP_010",
  "Hotspot_001", "Hotspot_002", "Hotspot_003", "Hotspot_004", "Hotspot_005",
  "Hotspot_006", "Hotspot_007", "Hotspot_008", "Hotspot_009", "Hotspot_010",
  "Guest_001", "Guest_002", "Guest_003", "Guest_004", "Guest_005",
  "Guest_006", "Guest_007", "Guest_008", "Guest_009", "Guest_010",
  "Free_001", "Free_002", "Free_003", "Free_004", "Free_005",
  "Free_006", "Free_007", "Free_008", "Free_009", "Free_010",
  "Public_001", "Public_002", "Public_003", "Public_004", "Public_005",
  "Public_006", "Public_007", "Public_008", "Public_009", "Public_010",
  "Open_001", "Open_002", "Open_003", "Open_004", "Open_005",
  "Open_006", "Open_007", "Open_008", "Open_009", "Open_010",
  "Secure_001", "Secure_002", "Secure_003", "Secure_004", "Secure_005",
  "Secure_006", "Secure_007", "Secure_008", "Secure_009", "Secure_010",
  "Private_001", "Private_002", "Private_003", "Private_004", "Private_005",
  "Private_006", "Private_007", "Private_008", "Private_009", "Private_010"
};

// Calculate the actual number of SSIDs
const int NUM_SSIDS = sizeof(SSID_LIST) / sizeof(SSID_LIST[0]);

// Define global variables
bool beacon_active = false;
uint8_t beacon_frame[BEACON_FRAME_SIZE];
uint8_t current_channel = 6;
uint32_t packet_counter = 0;
uint32_t start_time = 0;

// WiFi initialization
void beacon_setup() {
  Serial.println("BEACON FLOOD INITIALIZATION");

  WiFi.mode(WIFI_AP);
  delay(100);

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_AP);
  esp_wifi_start();

  esp_wifi_set_ps(WIFI_PS_NONE);

  esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);

  beacon_active = true;
  packet_counter = 0;
  start_time = millis();
}

// Generate a simple MAC address
void generate_mac(uint8_t* mac, int index) {
  mac[0] = 0x02;  // Locally administered
  mac[1] = 0x00;
  mac[2] = 0x00;
  mac[3] = (index >> 8) & 0xFF;
  mac[4] = index & 0xFF;
  mac[5] = random(256);
}

// Build and send a beacon frame
void send_beacon(int ssid_index) {
  uint8_t packet[BEACON_FRAME_SIZE];
  uint8_t mac[6];

  generate_mac(mac, ssid_index);

  // Get SSID
  const char* ssid = SSID_LIST[ssid_index % NUM_SSIDS];
  int ssid_len = strlen(ssid);
  if (ssid_len > MAX_SSID_LEN) ssid_len = MAX_SSID_LEN;

  // Build packet
  int pos = 0;

  // Frame control
  packet[pos++] = 0x80;  // Beacon
  packet[pos++] = 0x00;

  // Duration
  packet[pos++] = 0x00;
  packet[pos++] = 0x00;

  // Destination (broadcast)
  for (int i = 0; i < 6; i++) packet[pos++] = 0xFF;

  // Source MAC
  for (int i = 0; i < 6; i++) packet[pos++] = mac[i];

  // BSSID (same as source)
  for (int i = 0; i < 6; i++) packet[pos++] = mac[i];

  // Sequence control
  packet[pos++] = (packet_counter >> 4) & 0x0F;
  packet[pos++] = packet_counter & 0xFF;

  // Timestamp
  uint64_t timestamp = esp_timer_get_time();
  for (int i = 0; i < 8; i++) {
    packet[pos++] = (timestamp >> (i * 8)) & 0xFF;
  }

  // Beacon interval
  packet[pos++] = 0x64;  // 100 TU = 102.4ms
  packet[pos++] = 0x00;

  // Capability info
  packet[pos++] = 0x01;  // ESS
  packet[pos++] = 0x00;

  // SSID element
  packet[pos++] = 0x00;  // Element ID: SSID
  packet[pos++] = ssid_len;
  for (int i = 0; i < ssid_len; i++) {
    packet[pos++] = ssid[i];
  }

  // Supported rates
  packet[pos++] = 0x01;  // Element ID: Supported Rates
  packet[pos++] = 0x08;  // Length: 8
  packet[pos++] = 0x82;  // 1 Mbps
  packet[pos++] = 0x84;  // 2 Mbps
  packet[pos++] = 0x8b;  // 5.5 Mbps
  packet[pos++] = 0x96;  // 11 Mbps
  packet[pos++] = 0x0c;  // 6 Mbps
  packet[pos++] = 0x12;  // 9 Mbps
  packet[pos++] = 0x18;  // 12 Mbps
  packet[pos++] = 0x24;  // 18 Mbps

  // DS Parameter Set (channel)
  packet[pos++] = 0x03;  // Element ID: DS Parameter Set
  packet[pos++] = 0x01;  // Length
  packet[pos++] = current_channel;

  // Traffic Indication Map (TIM)
  packet[pos++] = 0x05;  // Element ID: TIM
  packet[pos++] = 0x04;  // Length: 4
  packet[pos++] = 0x00;  // DTIM Count
  packet[pos++] = 0x01;  // DTIM Period
  packet[pos++] = 0x00;  // Bitmap Control
  packet[pos++] = 0x00;  // Partial Virtual Bitmap

  esp_err_t result = esp_wifi_80211_tx(WIFI_IF_AP, packet, pos, false);

  if (result == ESP_OK) {
    packet_counter++;
  } else {
    static int error_count = 0;
    if (error_count++ % 100 == 0) {
      Serial.printf("Error sending beacon: %d\n", result);
    }
  }
}

void beacon_loop() {
  if (!beacon_active) return;

  static int ssid_index = 0;
  static unsigned long last_channel_change = 0;
  static unsigned long last_packet_time = 0;
  static unsigned long last_status_time = 0;

  unsigned long current_time = millis();

  if (current_time - last_packet_time >= 4) {
    send_beacon(ssid_index);
    ssid_index = (ssid_index + 1) % NUM_SSIDS;
    last_packet_time = current_time;

    if (packet_counter % 1000 == 0) {
      static unsigned long last_print = 0;
      if (current_time - last_print > 1000) {
        float rate = 1000.0 / (current_time - start_time);
        Serial.printf("Progress: %lu/%d packets (%.1f%%)\n",
                      packet_counter, NUM_SSIDS,
                      (packet_counter * 100.0) / NUM_SSIDS);
        last_print = current_time;
      }
    }
  }

  if (current_time - last_channel_change > 100) {
    if (current_channel == 1) current_channel = 6;
    else if (current_channel == 6) current_channel = 11;
    else current_channel = 1;

    esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
    last_channel_change = current_time;
  }
}

void stop_beacon() {
  beacon_active = false;

  Serial.println("Beacon stopped");
}

bool is_beacon_active() {
  return beacon_active;
}