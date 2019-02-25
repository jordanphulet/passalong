/***************************************************
  This is our GFX example for the Adafruit ILI9341 Breakout and Shield
  ----> http://www.adafruit.com/products/1651

  Check out the links above for our tutorials and wiring diagrams
  These displays use SPI to communicate, 4 or 5 pins are required to
  interface (RST is optional)
  Adafruit invests time and resources providing this open source code,
  please support Adafruit and open-source hardware by purchasing
  products from Adafruit!

  Written by Limor Fried/Ladyada for Adafruit Industries.
  MIT license, all text above must be included in any redistribution
 ****************************************************/


#include "SPI.h"
#include "Adafruit_GFX.h"
#include "Adafruit_ILI9341.h"

#include "qrcode.h"
#include "Wire.h"

// For the Adafruit shield, these are the default.
#define TFT_DC D3
#define TFT_CS D4

// Use hardware SPI (on Uno, #13, #12, #11) and the above for CS/DC
Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC);
// If using the breakout, change pins as desired
//Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_MOSI, TFT_CLK, TFT_RST, TFT_MISO);

  /*
  Serial.println("ILI9341 Test!"); 

	Serial.println("wake up device.");
	sha204.simpleWakeup();
	Serial.println("Sending a MAC Challenge.");
	Serial.println("Response is:");
	macChallengeExample();
	Serial.println("put device to sleep mode.");
	sha204.simpleSleep();
	Serial.println();
	delay(3000);
 
  tft.begin();

  // read diagnostics (optional but can help debug problems)
  uint8_t x = tft.readcommand8(ILI9341_RDMODE);
  Serial.print("Display Power Mode: 0x"); Serial.println(x, HEX);
  x = tft.readcommand8(ILI9341_RDMADCTL);
  Serial.print("MADCTL Mode: 0x"); Serial.println(x, HEX);
  x = tft.readcommand8(ILI9341_RDPIXFMT);
  Serial.print("Pixel Format: 0x"); Serial.println(x, HEX);
  x = tft.readcommand8(ILI9341_RDIMGFMT);
  Serial.print("Image Format: 0x"); Serial.println(x, HEX);
  x = tft.readcommand8(ILI9341_RDSELFDIAG);
  Serial.print("Self Diagnostic: 0x"); Serial.println(x, HEX); 
  
  Serial.print(F("Rectangles (filled)      "));
  Serial.println(testFilledRects(ILI9341_YELLOW, ILI9341_MAGENTA));
  delay(500);

  Serial.println(F("Done!"));

  delay(1000);
  pinMode(D2, OUTPUT);
  delay(3);
  pinMode(D2, INPUT);

  Serial.println("transmitted");

  Wire.requestFrom(0x64, 1);    // request 6 bytes from slave device #2
  while(Wire.available() == 0)    // slave may send less than requested
  {
    delay(1);
  }
  char c = Wire.read();    // receive a byte as character
  Serial.println(c);         // print the character
  */
  
  /*
  uint8_t data[1];
  uint8_t err = getResponse(data, 1);
  Serial.println(err);
  if (err == 0) {
    Serial.println(data[0], HEX);
  }
  */


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
#define OPCODE_MAC 0x08

// zone definitions
#define SHA204_ZONE_CONFIG              ((uint8_t)  0x00)      //!< Configuration zone
#define SHA204_ZONE_OTP                 ((uint8_t)  0x01)      //!< OTP (One Time Programming) zone
#define SHA204_ZONE_DATA                ((uint8_t)  0x02)      //!< Data zone

#define ADDRESS_SN03 0	// SN[0:3] are bytes 0->3 of configuration zone

#define MAX_PACKET_SIZE 18

// opcodes
#define ATSHA204A_OPCODE_MAC 0x08

// command delays
#define ATSHA204A_CMD_DELAY_MAC 12

// data sizes
#define ATSHA204A_DATA_SIZE_MAC 32

// response sizes
#define ATSHA204A_RESP_SIZE_MAC 32

void setup() {
  Wire.begin();
  Serial.begin(9600);

  // send mac command
  uint8_t challenge[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  uint8_t response[ATSHA204A_RESP_SIZE_MAC];
	uint8_t err = commandMac(challenge, 0x00, response);
}

uint8_t commandMac(uint8_t* challenge, uint8_t keySlot, uint8_t* response) {
  return command(
    ATSHA204A_OPCODE_MAC,
    0x00,
    keySlot << 8,
    ATSHA204A_DATA_SIZE_MAC, challenge,
    ATSHA204A_RESP_SIZE_MAC, response,
    ATSHA204A_CMD_DELAY_MAC
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
  // wake
  uint8_t err = wake();
  if (err != 0) {
    return ERR_WAKE_FAILED;
  }

  // send command
	err = sendCommand(opcode, param1, param2, dataSize, data);
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

  // DEBUG
  Serial.print("SENDING: ");
  for (int i = 0; i < requestSize; i++) {
    if (request[i] < 0x10) {
      Serial.print("0x0");
    } else {
      Serial.print("0x");
    }
    Serial.print(request[i], HEX);
    Serial.print(" ");
  }
  Serial.println();

  uint8_t bytesWritten = 0;
  while(bytesWritten < requestSize) {
    Wire.beginTransmission(SHA204A_ADDR);
    Wire.write(SHA204_SWI_FLAG_CMD);

    uint8_t bytesToWrite = min(MAX_PACKET_SIZE - 1, requestSize - bytesWritten);

    bytesWritten += Wire.write(request + bytesWritten, bytesToWrite);
    uint8_t err = Wire.endTransmission();
    if (err != 0) {
      return ERR_NACK;
    }
  }

  // OK
  return ERR_OK;
}

void printHexByte(uint8_t data) {
  Serial.print("0x");
  if (data < 0x0F) {
    Serial.print("0");
  }
  Serial.print(data, HEX);
  Serial.print(" ");
}

uint8_t getResponse(uint8_t dataSize, uint8_t* data) {
  // trivial case
  if (dataSize < 1) {
    return ERR_OK;
  }

  // send transmit flag
  delay(3);
  Wire.beginTransmission(SHA204A_ADDR);
  Wire.write(0x88);
  uint8_t err = Wire.endTransmission();
  if (err != 0) {
    return ERR_TRANSMISSION_FAILED;
  }

  // get count
  Wire.requestFrom(SHA204A_ADDR, 1);
  if (!Wire.available()) {
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
    if (!Wire.available()) {
      return ERR_NO_BYTES_AVAILABLE;
    }
    for (int i = 0; i < newBytes; i++) {
      response[i + bytesReceived] = Wire.read();
    }
    bytesReceived += newBytes;
  }

  Serial.print("RESPONSE: ");
  for (uint8_t i = 0; i < count; i++) {
    printHexByte(response[i]);
  }
  Serial.println();

  // check CRC
  uint8_t crc[2];
  calculateCrc(count - 2, response, crc);
  if (crc[0] != response[count - 2] || crc[1] != response[count-1]) {
    Serial.println("BAD CRC!");
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

unsigned long testFilledRects(uint16_t color1, uint16_t color2) {
  tft.fillScreen(ILI9341_WHITE);
  yield();

  QRCode qrcode;
  uint8_t qv = 6;
  uint8_t scale = 5;
  uint8_t margin = 15;

  uint8_t qrcodeData[qrcode_getBufferSize(qv)];
  qrcode_initText(&qrcode, qrcodeData, qv, 1, "11111222223333344444555556666677777888889999900000");

  for (uint8_t y = 0; y < qrcode.size; y++) {
    for (uint8_t x = 0; x < qrcode.size; x++) {
      if(qrcode_getModule(&qrcode, x, y)) {
        tft.fillRect(margin + x*scale, margin + y*scale, scale, scale, ILI9341_BLACK);
      }
    }
  }
  yield();
  return 0;
}

