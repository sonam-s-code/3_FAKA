#include <Wire.h>
#include <SPI.h>
#include <Adafruit_PN532.h>
#include <Adafruit_Fingerprint.h>
#include <SoftwareSerial.h>

// ------------------ NFC SETUP ---------------------
#define SDA_PIN A4
#define SCL_PIN A5
Adafruit_PN532 nfc(SDA_PIN, SCL_PIN);
uint8_t keya[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

// ------------------ FINGERPRINT SETUP ---------------------
SoftwareSerial mySerial(2, 3); // RX, TX
Adafruit_Fingerprint finger(&mySerial);

// ------------------ SERIAL CONTROL ---------------------
char serialInput[32];  // Instead of String serialInput
bool waitForDataInput = false;
bool waitingForEnrollID = false;

// ======================================================
void setup() {
  Serial.begin(115200);
  while (!Serial);
  //Serial.println("🔐 NFC + Fingerprint System Ready.");
  //Serial.println(F("📌 Commands: read | change data | fingerprint | enroll | delete"));

  Wire.begin();
  nfc.begin();
  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata) {
    Serial.println("❌ NFC module not found!");
    while (1);
  }
  nfc.SAMConfig();

  finger.begin(57600);
  delay(5);
  if (finger.verifyPassword()) {
    Serial.println("✅ Fingerprint sensor found.");
    finger.getTemplateCount();
    //Serial.print("📂 Stored fingerprints: ");
   // Serial.println(finger.templateCount);
  } else {
    Serial.println("❌ Fingerprint sensor not found!");
    while (1);
  }
}

// ======================================================
void loop() {
if (Serial.available()) {
    size_t len = Serial.readBytesUntil('\n', serialInput, sizeof(serialInput) - 1);
    serialInput[len] = '\0';  // Null-terminate

    if (waitForDataInput) {
      writeToCard(serialInput);
      waitForDataInput = false;
      Serial.println(F("✅ Data written to card."));
    } else if (strcmp(serialInput, "read") == 0) {
      readFromCard();
    } else if (strcmp(serialInput, "change data") == 0) {
      Serial.println(F("✏️ Writing....."));
      waitForDataInput = true;
    } else if (strcmp(serialInput, "fingerprint") == 0) {
      Serial.println(F("👉 Place your finger..."));
      delay(5000);
      getFingerprintID();
    } else if (strcmp(serialInput, "enroll") == 0) {
      Serial.println(F("📥 Enter ID to enroll (0–127):"));
      while (!Serial.available());
      int enrollId = Serial.parseInt();
      enrollFingerprint(enrollId);
    } else if (strcmp(serialInput, "delete") == 0) {
      //Serial.println(F("🗑️ Enter ID to delete (1–127):"));
      while (!Serial.available());
      int deleteId = Serial.parseInt();
      deleteFingerprint(deleteId);
    } else {
//      Serial.println(F("⚠️ Unknown command. Try: read | change data | fingerprint | enroll | delete"));
    }
  }
}

// ======================================================
void readFromCard() {
  Serial.println("📡 Tap NFC tag...");

  uint8_t uid[7]; 
  uint8_t uidLength;

  if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength)) {
    Serial.print("🆔 UID: ");
    for (uint8_t i = 0; i < uidLength; i++) {
      Serial.print(" 0x"); Serial.print(uid[i], HEX);
    }
    Serial.println();

    String fullData = "";
    int startBlock = 4;
    int blocksToRead = 3;

    for (int i = 0; i < blocksToRead; i++) {
      int block = startBlock + i;

      if (!nfc.mifareclassic_AuthenticateBlock(uid, uidLength, block, 0, keya)) {
        //Serial.print("❌ Authentication failed for block ");
        //Serial.println(block);
        return;
      }

      uint8_t data[16];
      if (nfc.mifareclassic_ReadDataBlock(block, data)) {
        for (int j = 0; j < 16; j++) {
          if (data[j] >= 32 && data[j] <= 126) {
            fullData += (char)data[j];
          }
        }
      } else {
       // Serial.print("❌ Read failed for block ");
        //Serial.println(block);
        return;
      }
    }

    Serial.print("📖 NFC Data: ");
    Serial.println(fullData);
  } else {
    Serial.println("❌ No NFC tag detected.");
  }
}


// ======================================================
void writeToCard(String content) {
  Serial.println("📡 Tap NFC tag to write...");

  uint8_t uid[7]; 
  uint8_t uidLength;
  
  // Wait for tag
  while (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength));

  Serial.print("🆔 UID: ");
  for (uint8_t i = 0; i < uidLength; i++) {
    Serial.print(" 0x"); Serial.print(uid[i], HEX);
  }
  Serial.println();

  int maxBlocks = 3;  // Write to 3 blocks: 4, 5, 6
  int blockStart = 4;
  int contentLen = content.length();
  int bytesWritten = 0;

  for (int i = 0; i < maxBlocks && bytesWritten < contentLen; i++) {
    int blockNum = blockStart + i;

    // Authenticate the block
    if (!nfc.mifareclassic_AuthenticateBlock(uid, uidLength, blockNum, 0, keya)) {
      //Serial.print("❌ Authentication failed for block ");
      //Serial.println(blockNum);
      return;
    }

    // Prepare 16-byte chunk
    uint8_t data[16] = {0};
    for (int j = 0; j < 16 && bytesWritten < contentLen; j++, bytesWritten++) {
      data[j] = content[bytesWritten];
    }

    // Write the block
    if (!nfc.mifareclassic_WriteDataBlock(blockNum, data)) {
      //Serial.print("❌ Write failed for block ");
     // Serial.println(blockNum);
      return;
    } else {
      //Serial.print("✅ Written to block ");
      //Serial.println(blockNum);
    }
  }

  Serial.println("✅ All data written successfully!");
}

// ======================================================
uint8_t getFingerprintID() {
  uint8_t p = finger.getImage();
  if (p != FINGERPRINT_OK) {
    Serial.println("❌ No finger detected or scan failed.");
    return p;
  }

  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) {
    Serial.println("❌ Image conversion failed.");
    return p;
  }

  p = finger.fingerSearch();
  if (p == FINGERPRINT_OK) {
    Serial.print("✅ Match Found! ID: ");
    Serial.print(finger.fingerID);
    Serial.print(" | Confidence: ");
    Serial.println(finger.confidence);
  } else if (p == FINGERPRINT_NOTFOUND) {
    Serial.println("❌ No match found.");
  } else {
    Serial.println("❌ Fingerprint scan error.");
  }
  return p;
}

// ======================================================
void enrollFingerprint(int id) {
  if (id < 0 || id > 127) {
    Serial.println(F("❌ Invalid ID. Use 0–127."));
    return;
  }

  Serial.print(F("🖐️ Place finger to enroll ID ")); Serial.println(id);
  while (finger.getImage() != FINGERPRINT_OK);
  if (finger.image2Tz(1) != FINGERPRINT_OK) {
    Serial.println(F("❌ Failed to convert image."));
    return;
  }

  Serial.println(F("✋ Remove and place finger again."));
  delay(2000);
  while (finger.getImage() != FINGERPRINT_OK);
  if (finger.image2Tz(2) != FINGERPRINT_OK) {
    Serial.println(F("❌ Failed to convert second image."));
    return;
  }

  if (finger.createModel() != FINGERPRINT_OK) {
    Serial.println(F("❌ Model creation failed."));
    return;
  }

  if (finger.storeModel(id) == FINGERPRINT_OK) {
    Serial.println(F("✅ Fingerprint enrolled successfully!"));
  } else {
    Serial.println(F("❌ Failed to store fingerprint."));
  }
}
uint8_t deleteFingerprint(uint8_t id) {
  if (id <= 0 || id > 127) {
    Serial.println(F("❌ Invalid ID."));
    return FINGERPRINT_BADLOCATION;
  }

  uint8_t p = finger.deleteModel(id);

  switch (p) {
    case FINGERPRINT_OK:
      Serial.println(F("✅ Fingerprint deleted."));
      break;
    case FINGERPRINT_PACKETRECIEVEERR:
      Serial.println(F("❌ Communication error."));
      break;
    case FINGERPRINT_BADLOCATION:
      Serial.println(F("❌ Fingerprint not found in that ID."));
      break;
    case FINGERPRINT_FLASHERR:
      Serial.println(F("❌ Flash write error."));
      break;
    default:
      Serial.print(F("❌ Unknown error: 0x")); Serial.println(p, HEX);
      break;
  }

  return p;
}
