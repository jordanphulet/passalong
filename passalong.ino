#include "SPI.h"
#include "Adafruit_GFX.h"
#include "qrcode.h"
#include "Wire.h"
#include <base64.hpp>

#define SHA204A_ADDR 0x64

#define ERR_OK 0x00
#define ERR_BAD_CRC 0x01
#define ERR_BAD_RESPONSE_SIZE 0x02
#define ERR_TRANSMISSION_FAILED 0x03
#define ERR_NO_BYTES_AVAILABLE 0x04
#define ERR_NACK 0x05
#define ERR_WAKE_FAILED 0x06

#define SHA204_SWI_FLAG_CMD     ((uint8_t) 0x03) //!< flag preceding a command
#define SHA204_SWI_FLAG_TX      ((uint8_t) 0x00) //!< flag requesting a response
#define SHA204_SWI_FLAG_IDLE    ((uint8_t) 0x02) //!< flag requesting to go into Idle mode
#define SHA204_SWI_FLAG_SLEEP   ((uint8_t) 0x01) //!< flag requesting to go into Sleep mode

#define COUNT_SIZE 1
#define OPCODE_SIZE 1
#define PARAM1_SIZE 1
#define PARAM2_SIZE 2
#define CRC_SIZE 2

#define COMMAND_MAC_SIZE 32

// zone definitions
#define SHA204_ZONE_CONFIG              ((uint8_t)  0x00)      //!< Configuration zone
#define SHA204_ZONE_OTP                 ((uint8_t)  0x01)      //!< OTP (One Time Programming) zone
#define SHA204_ZONE_DATA                ((uint8_t)  0x02)      //!< Data zone

#define ADDRESS_SN03 0  // SN[0:3] are bytes 0->3 of configuration zone

#define MAX_PACKET_SIZE 18

#define ATSHA204A_ZONE_ENCODING_CONFIG 0
#define ATSHA204A_ZONE_ENCODING_OTP    1
#define ATSHA204A_ZONE_ENCODING_DATA   2

// opcodes
#define ATSHA204A_OPCODE_READ   0x02
#define ATSHA204A_OPCODE_MAC    0x08
#define ATSHA204A_OPCODE_WRITE  0x12
#define ATSHA204A_OPCODE_NONCE  0x16
#define ATSHA204A_OPCODE_RANDOM 0x1B

// command delays
#define ATSHA204A_CMD_DELAY_READ   4
#define ATSHA204A_CMD_DELAY_MAC    35
#define ATSHA204A_CMD_DELAY_WRITE  42
#define ATSHA204A_CMD_DELAY_NONCE  60
#define ATSHA204A_CMD_DELAY_RANDOM 50

// data sizes
#define ATSHA204A_DATA_SIZE_MAC 32

// response sizes
#define ATSHA204A_RESP_SIZE_MAC 32
#define ATSHA204A_RESP_SIZE_RANDOM 32

#define MCP23017_ADDR 0x20

/*
#include <Adafruit_ST7735.h>
#define TFT_CS 16
#define TFT_RST 9
#define TFT_DC 17
#define TFT_SCLK 5
#define TFT_MOSI 23
#define COLOR_WHITE ST7735_WHITE
#define COLOR_BLACK ST7735_BLACK
#define QR_SCALE 2
#define QR_MARGIN 14
Adafruit_ST7735 tft = Adafruit_ST7735(TFT_CS, TFT_DC, TFT_MOSI, TFT_SCLK, TFT_RST);
*/

#include "Adafruit_ILI9341.h"
#define TFT_DC D4
#define TFT_CS D3
#define COLOR_WHITE ILI9341_WHITE
#define COLOR_BLACK ILI9341_BLACK
#define QR_SCALE 4
#define QR_MARGIN 22
Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC);

#define ATSHA_DEBUG 1

void setup() {
  Wire.begin();

  #if ATSHA_DEBUG
  Serial.begin(9600);
  while (!Serial);
  #endif

  /*
  // TESTING WRITE AND READ

  wake();
  uint8_t toWrite[32] = {
    0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
    0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
    0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13,
    0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13
  };
  uint8_t readResponse[32];
  commandWrite(ATSHA204A_ZONE_ENCODING_DATA, 8, toWrite);
  commandRead(ATSHA204A_ZONE_ENCODING_DATA, 8, readResponse);
  sleep();
  */

  // initialize MCP23017 (set all pull-ups on)
  Wire.beginTransmission(MCP23017_ADDR);
  Wire.write(0x0D);
  Wire.write(0xFF);
  Wire.endTransmission();

  // get URL
  uint8_t code[128]; // more than enough room (44 + 44 + 28 + 2)
  generateCode(code, readDip());
  encodeParams((char*)code);
  char url[200];
  strcpy(url, "https://passthe.ninja/?t=");
  strcat(url, (char*)code);

  #if ATSHA_DEBUG
  Serial.println(url);
  #endif

  //tft.initR();
  tft.begin();
  tft.fillScreen(COLOR_WHITE);
  drawQr(url);
}

void encodeParams(char* params) {
  uint8_t i = 0;
  while (params[i] != 0) {
    if (params[i] == ' ') {
      params[i] = '~';
    }
    else if (params[i] == '+') {
      params[i] = '_';
    }
    else if (params[i] == '=') {
      params[i] = '-';
    }
    i++;
  }
}

uint8_t readDip() {
  uint8_t inputs;
  Wire.beginTransmission(MCP23017_ADDR);
  Wire.write(0x13);
  Wire.endTransmission();
  Wire.requestFrom(MCP23017_ADDR, 1);
  inputs = ~Wire.read();
  #if ATSHA_DEBUG
  Serial.println(inputs, BIN);
  #endif
  return inputs;
}

void readHistory(uint8_t* history) {
  for( int i = 0; i < 10; i++) {
    history[i] = 0x11;
  }
}

void generateCode(uint8_t* code, uint8_t dip) {
  uint8_t numIn[20];

  // wake the device
  wake();

  // set first byte of numIn to value of DIP
  numIn[0] = dip;

  // read the serial number into bytes 1-9 of numIn
  readSerialNumber(numIn + 1);

  // read the history bytes in to bytes 10-19 of numIn
  readHistory(numIn + 10);

  // send nonce command, returns random number used to generate nonce
  uint8_t nonceResponse[32];
  commandNonce(false, numIn, nonceResponse);

  // send mac command
  uint8_t macResponse[ATSHA204A_RESP_SIZE_MAC];
  commandMac(0x00, macResponse);

  // put the device to sleep
  sleep();

  #if ATSHA_DEBUG
  Serial.println("NUMIN:");
  printBase64(20, numIn);
  Serial.println("RNG:");
  printBase64(32, nonceResponse);
  Serial.println("MAC:");
  printBase64(ATSHA204A_RESP_SIZE_MAC, macResponse);
  #endif

  unsigned int codeBytes = 0;
  // mac
  codeBytes += encode_base64(macResponse, 32, code + codeBytes);
  code[codeBytes++] = '.';
  // rng
  codeBytes += encode_base64(nonceResponse, 32, code + codeBytes);
  code[codeBytes++] = '.';
  // numin
  codeBytes += encode_base64(numIn, 20, code + codeBytes);
}

void drawQr(char* code) {

  QRCode qrcode;
  uint8_t qv = 8;
  uint8_t scale = QR_SCALE;
  uint8_t margin = QR_MARGIN;

  uint8_t qrcodeData[qrcode_getBufferSize(qv)];
  qrcode_initText(&qrcode, qrcodeData, qv, 1, code);

  for (uint8_t y = 0; y < qrcode.size; y++) {
    for (uint8_t x = 0; x < qrcode.size; x++) {
      if(qrcode_getModule(&qrcode, x, y)) {
        tft.fillRect(margin + x*scale, margin + y*scale, scale, scale, COLOR_BLACK);
      }
    }
  }
}

void readSerialNumber(uint8_t* serialNumber) {
  // serial number is a subset of the first 32 bytes of the config
  uint8_t readResponse[32];
  commandRead(ATSHA204A_ZONE_ENCODING_CONFIG, 0, readResponse);

  uint8_t offset = 0;
  // first word
  memcpy(serialNumber, readResponse, 4);

  // third word
  memcpy(serialNumber + 4, readResponse + 8, 4);

  // first byte of fourth word
  serialNumber[8] = readResponse[12];
}

uint8_t commandRandom(uint8_t* response) {
  return command(
    ATSHA204A_OPCODE_RANDOM,
    0x00,
    0x0000,
    0, 0,
    ATSHA204A_RESP_SIZE_RANDOM, response,
    ATSHA204A_CMD_DELAY_RANDOM
  );
}

uint8_t commandRead(uint8_t zoneEncoding, uint8_t slot, uint8_t* response) {
  // only reading 32 bytes
  uint8_t zone = 0b10000000;
  // set zone encoding bits
  zone |= zoneEncoding;

  uint16_t address = slot << 11;

  return command(
    ATSHA204A_OPCODE_READ,
    zone,
    address,
    0, 0,
    32, response,
    ATSHA204A_CMD_DELAY_READ
  );
}

uint8_t commandWrite(uint8_t zoneEncoding, uint8_t slot, uint8_t* data) {
  // only writing 32 bytes in the clear
  uint8_t zone = 0b10000000;
  // set zone encoding bits
  zone |= zoneEncoding;

  uint16_t address = slot << 11;

  uint8_t response;

  return command(
    ATSHA204A_OPCODE_WRITE,
    zone,
    address,
    32, data,
    1, &response,
    ATSHA204A_CMD_DELAY_WRITE
  );
}

uint8_t commandMac(uint8_t keySlot, uint8_t* response) {
  // mode
  //   7: 0
  //   6: include SN bits
  //   5: include 64 OTP bits
  //   4: include 88 OTP bits (overrides 6 if set)
  //   3: 0
  //   2: if 0 or 1 are set, must match TempKey.SourceFlag (0=random, 1=input)
  //   1: 1st 32 bytes from from TempKey, otherwise from data slot
  //   0: 2nd 32 bytes from from TempKey, otherwise from challenge parameter 

  //uint8_t mode = 0x05;
  uint8_t mode = 0b00000001; // no extra SN/OTP bits, key from slot, not using challenge param, temp key random
  return command(
    ATSHA204A_OPCODE_MAC,
    mode,
    keySlot << 8,
    0, 0,
    ATSHA204A_RESP_SIZE_MAC, response,
    ATSHA204A_CMD_DELAY_MAC
  );
}

uint8_t commandNonce(boolean passThrough, uint8_t* numIn, uint8_t* response) {
  // in passthrough mode the response is 0x00, otherwise it is the 32 byte output of the RNG
  uint8_t responseSize = passThrough ? 1 : 32;

  // in passthorough mode the data is the 32 byte input, otherwise the 20 byte
  // input is used in the SHA which also includes the output of the RNG
  uint8_t dataSize = passThrough ? 32 : 20;

  // always update the seed if not in passthrough mode
  uint8_t mode = passThrough ? 0x03 : 0x00;

  return command(
    ATSHA204A_OPCODE_NONCE,
    mode,
    0x0000,
    dataSize, numIn,
    responseSize, response,
    ATSHA204A_CMD_DELAY_NONCE
  );
}

uint8_t command(
  uint8_t  opcode,
  uint8_t  param1,
  uint16_t param2,
  uint8_t  dataSize,     uint8_t* data,
  uint8_t  responseSize, uint8_t* response,
  uint8_t  cmdDelay
) {
  // send command
  uint8_t err = sendCommand(opcode, param1, param2, dataSize, data);
  if (err != 0) {
    return err;
  }

  // delay for command completion
  delay(cmdDelay);

  // get response
  return getResponse(responseSize, response);
}

uint8_t sendCommand(uint8_t opcode, uint8_t param1, uint16_t param2, uint8_t dataSize, uint8_t* data) {
  uint8_t requestSize = COUNT_SIZE + OPCODE_SIZE + PARAM1_SIZE + PARAM2_SIZE + dataSize + CRC_SIZE; 
  uint8_t request[requestSize];

  // copy count
  request[0] = requestSize;

  // copy opcode
  request[COUNT_SIZE] = opcode;

  // copy param1
  request[COUNT_SIZE + OPCODE_SIZE] = param1;

  // copy param2
  request[COUNT_SIZE + OPCODE_SIZE + PARAM1_SIZE] = param2 >> 8;
  request[COUNT_SIZE + OPCODE_SIZE + PARAM1_SIZE + 1] = param2 & 0xFF;

  // copy data
  for (uint8_t i = 0; i < dataSize; i++) {
    request[i + COUNT_SIZE + OPCODE_SIZE + PARAM1_SIZE + PARAM2_SIZE] = data[i];
  }

  // add CRC to request
  uint8_t crcDataSize = requestSize - CRC_SIZE;
  uint8_t* crc = request + requestSize - CRC_SIZE;
  calculateCrc(crcDataSize, request, crc);

  #if ATSHA_DEBUG
  Serial.print("SENDING: ");
  for (int i = 0; i < requestSize; i++) {
    printHexByte(request[i]);
  }
  Serial.println();
  #endif

  uint8_t bytesWritten = 0;
  while(bytesWritten < requestSize) {
    Wire.beginTransmission(SHA204A_ADDR);
    Wire.write(SHA204_SWI_FLAG_CMD);

    uint8_t bytesToWrite = min(MAX_PACKET_SIZE - 1, requestSize - bytesWritten);

    bytesWritten += Wire.write(request + bytesWritten, bytesToWrite);
    uint8_t err = Wire.endTransmission();
    if (err != 0) {
      // TODO: why is this happening sometimes when calling write comand?
      Serial.println("NACK ERROR!");
      Serial.println(err);
      return ERR_NACK;
    }
  }

  // OK
  return ERR_OK;
}

void printHexByte(uint8_t data) {
  Serial.print("0x");
  if (data < 0x10) {
    Serial.print("0");
  }
  Serial.print(data, HEX);
  Serial.print(" ");
}

void printBase64(uint8_t len, uint8_t* bytes) {
    uint8_t base64[64];
    encode_base64(bytes, len, base64);
    Serial.println((char*)base64);
}

bool wireWait() {
  uint8_t retries = 3;
  while (!Wire.available()) {
    retries--;
    if (retries < 0) {
      return false;
    }
    delay(20);
  }
  return true;
}

uint8_t getResponse(uint8_t dataSize, uint8_t* data) {
  // trivial case
  if (dataSize < 1) {
    return ERR_OK;
  }

  uint8_t retries = 5;
  while(true) {
    retries--;
    // send transmit flag
    delay(3);
    Wire.beginTransmission(SHA204A_ADDR);
    Wire.write(0x88);
    uint8_t err = Wire.endTransmission();
    if (err == 0) {
      break;
    }
    else if (retries < 0) {
      Serial.println("RESPONSE TRANSMISSION FAILED ERROR!");
      Serial.println(err);
      return ERR_TRANSMISSION_FAILED;
    }
  }

  // get count
  Wire.requestFrom(SHA204A_ADDR, 1);
  if (!wireWait()) {
    Serial.println("COUNT NO BYTES AVAILABLE ERROR!");
    return ERR_NO_BYTES_AVAILABLE;
  }

  // initialize response buffer
  uint8_t count = Wire.read();
  uint8_t response[count];
  response[0] = count;

  // get all the bytes
  uint8_t bytesReceived = 1;
  while (bytesReceived < count) {
    uint8_t newBytes = Wire.requestFrom(SHA204A_ADDR, count - bytesReceived);
    if (!wireWait()) {
      Serial.println("RESPONSE NO BYTES AVAILABLE ERROR!");
      return ERR_NO_BYTES_AVAILABLE;
    }
    for (int i = 0; i < newBytes; i++) {
      response[i + bytesReceived] = Wire.read();
    }
    bytesReceived += newBytes;
  }

  #if ATSHA_DEBUG
  Serial.print("RESPONSE: ");
  for (uint8_t i = 0; i < count; i++) {
    printHexByte(response[i]);
  }
  Serial.println();
  #endif

  // check CRC
  uint8_t crc[2];
  calculateCrc(count - 2, response, crc);
  if (crc[0] != response[count - 2] || crc[1] != response[count-1]) {
    Serial.println("BAD CRC ERROR!");
    return ERR_BAD_CRC;
  }

  // copy data
  for (int i = 0; i < dataSize; i++) {
    if (i + 1 >= count) {
      break;
    }
    data[i] = response[i + 1];
  }

  // OK
  return ERR_OK;
}

uint8_t wake() {
  // hold SDA low
  Wire.beginTransmission(0x00);
  Wire.endTransmission();

  // delay for device wakeup
  delay(3);

  // send transmit flag
  Wire.beginTransmission(SHA204A_ADDR);
  Wire.write(0x88);
  uint8_t err = Wire.endTransmission();
  if (err != 0) {
    Serial.println("WAKE END TRANSMISSION FAILED ERROR!");
    return ERR_TRANSMISSION_FAILED;
  }

  // get 0x11 response
  uint8_t response[2];
  err = getResponse(2, response);
  if (err != 0) {
    return err;
  }

  // OK
  return ERR_OK;
}

uint8_t sleep() {
  Wire.beginTransmission(SHA204A_ADDR);
  Wire.write(0xCC);
  uint8_t err = Wire.endTransmission();
  if (err != 0) {
    Serial.println("SLEEP END TRANSMISSION FAILED ERROR!");
    return ERR_TRANSMISSION_FAILED;
  }

  // OK
  return ERR_OK;
}

void calculateCrc(uint8_t length, uint8_t *data, uint8_t *crc) {
  uint8_t counter;
  uint16_t crc_register = 0;
  uint16_t polynom = 0x8005;
  uint8_t shift_register;
  uint8_t data_bit, crc_bit;

  for (counter = 0; counter < length; counter++) {
    for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1) {
      data_bit = (data[counter] & shift_register) ? 1 : 0;
      crc_bit = crc_register >> 15;

      // Shift CRC to the left by 1.
      crc_register <<= 1;

      if ((data_bit ^ crc_bit) != 0)
        crc_register ^= polynom;
    }
  }

  crc[0] = (uint8_t) (crc_register & 0x00FF);
  crc[1] = (uint8_t) (crc_register >> 8);
}

void loop(void) {
  delay(1000);
}
