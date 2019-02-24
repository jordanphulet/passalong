#include "pindeclarations.h"
#include <util/delay.h>
#include <base64.hpp>

// I2C settings
uint8_t I2C_DELAY_CYCLES = 2;

#define I2C_READ 1
#define I2C_WRITE 0
#define NOREPEATSTART 0
#define REPEATSTART 1

#define TWI_SDA_PIN PC4
#define TWI_SCL_PIN PC5

#define cryptoauth_address 0xC8
#define PACKET_COUNT 0

#define FUNCTION_RESET 0x00
#define FUNCTION_SLEEP 0x01
#define FUNCTION_IDLE 0x02
#define FUNCTION_COMMAND 0x03

#define COMMAND_READ 0x02
#define COMMAND_WRITE 0x12
#define COMMAND_MAC 0x08
#define COMMAND_NONCE 0x16

#define ZONE_ENCODING_DATA 2

#define NONCE_PASS_THROUGH 0x03

#define READ_32_BYTES 0x80

#define KEY_SLOT 0x00
#define NONCE_COUNT_SLOT 0x08

uint8_t data_out[40];
uint8_t data_in[35];
uint8_t crc[2];
uint8_t counter = 0;

#include <SPI.h>
#include <Wire.h>
#include <Adafruit_SSD1306.h>
#include "qrcode.h"

#define SCREEN_WIDTH 128 // OLED display width, in pixels
#define SCREEN_HEIGHT 64 // OLED display height, in pixels
#define OLED_RESET     4 // Reset pin # (or -1 if sharing Arduino reset pin)
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

/*
void setup() {
}
*/

void setup() {
  Serial.begin(9600);

  // Initialse I2C
  DDRC &= ~(1<<TWI_SCL_PIN);
  PORTC &= ~(1<<TWI_SCL_PIN);
  DDRC &= ~(1<<TWI_SDA_PIN);
  PORTC &= ~(1<<TWI_SDA_PIN);

  uint8_t otp[40];
  generateMac(otp);
  printBase64(otp, 40);

  // SSD1306_SWITCHCAPVCC = generate display voltage from 3.3V internally
  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) { // Address 0x3D for 128x64
    Serial.println(F("SSD1306 allocation failed"));
    for(;;); // Don't proceed, loop forever
  }

  QRCode qrcode;
  uint8_t qrcodeData[qrcode_getBufferSize(4)];
  qrcode_initText(&qrcode, qrcodeData, 4, 0, "wpgUpNVNr1Clz75KwuTAwpgUpNVNr1Clz75KwuTAwpgUpNVNr1Clz75KwuTA");

	Serial.println("QR");

  display.clearDisplay();

  display.fillRect(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT, WHITE);
  
  uint8_t xOffset = 0;//(SCREEN_WIDTH - qrcode.size*2) / 2;
  uint8_t yOffset = 0;//(SCREEN_HEIGHT - qrcode.size*2) / 2;

  for (uint8_t y = 0; y < qrcode.size; y++) {
        // Each horizontal module
        for (uint8_t x = 0; x < qrcode.size; x++) {
            if(qrcode_getModule(&qrcode, x, y)) {
							/*
              display.drawPixel(xOffset + x*2, yOffset + y*2, BLACK );
              display.drawPixel(xOffset + x*2+1, yOffset + y*2, BLACK );
              display.drawPixel(xOffset + x*2, yOffset + y*2+1, BLACK );
              display.drawPixel(xOffset + x*2+1, yOffset + y*2+1, BLACK );
*/
            }
        }
    }

  display.dim(true);
  display.display();

	Serial.println("DONE");
}

void loop() {
  delay(200);
}

void printBase64(uint8_t* bytes, uint8_t len) {
    char base64[64];
    encode_base64(bytes, len, base64);
    Serial.println((char*)base64);
}

void readData(uint8_t slot, uint8_t* data) {
  sha204a_wakeup();
  sha204a_read(slot << 3, READ_32_BYTES, ZONE_ENCODING_DATA);
  sha204a_read_buffer();
  sha204a_sleep();

  for (uint8_t x = 0; x < 32; x++) {
    data[x] = data_in[x+1];
  }
}

uint32_t getNonceCount(uint8_t* nonceData) {
  readData(NONCE_COUNT_SLOT, nonceData);

  uint32_t count = nonceData[28];
  for (int i = 1; i < 4; i++) {
    count = count << 8;
    count += nonceData[28+i];
  }

  return count;
}

uint32_t incrementNonceCount() {
  uint8_t nonceData[32];
  uint32_t count = getNonceCount(nonceData) + 1;
  nonceData[31] = count & 0xFF;
  for (int i = 1; i < 4; i++) {
    count = count >> 8;
    nonceData[31-i] = count & 0xFF;
  }
  writeData(NONCE_COUNT_SLOT, nonceData);
}

void loadNonce(uint8_t* nonceOut) {
  uint8_t nonceData[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  uint32_t count = getNonceCount(nonceData);
  
  sha204a_wakeup();
  
  if (soft_i2c_master_start(cryptoauth_address | I2C_WRITE)) {
    data_out[0] = FUNCTION_COMMAND; // command
    data_out[1] = 7 + 32; // count (included in count)
    data_out[2] = COMMAND_NONCE;
    data_out[3] = NONCE_PASS_THROUGH;
    data_out[4] = 0;
    data_out[5] = 0;
          
    for (uint8_t x = 0; x < 32; x++) {
      data_out[x+6] = nonceData[x];
    }
    
    sha204c_calculate_crc(5 + 32, &data_out[1], crc); // crc starts at count

    soft_i2c_master_start(cryptoauth_address | I2C_WRITE);
    for (uint8_t x = 0; x < 6 + 32; x++) {
      soft_i2c_master_write(data_out[x]);    
    }
    soft_i2c_master_write(crc[0]); 
    soft_i2c_master_write(crc[1]);
    soft_i2c_master_stop();

    delay(60);
    
    sha204a_read_buffer();
    sha204a_idle();
  }

  for (int i = 0; i < 8; i++) {
    nonceOut[i] = nonceData[24 + i];
  }
}

void generateMac(uint8_t* otp) {
  loadNonce(otp + 32);

  sha204a_wakeup();
  
  if (soft_i2c_master_start(cryptoauth_address | I2C_WRITE)) {
    data_out[0] = FUNCTION_COMMAND; // command
    data_out[1] = 7; // count (included in count)
    data_out[2] = COMMAND_MAC;
    data_out[3] = 0x05; //mode, TempKey.SourceFlag, 1 = Input
    data_out[4] = KEY_SLOT;
    data_out[5] = 0;
     
    sha204c_calculate_crc(5, &data_out[1], crc); // crc starts at count

    soft_i2c_master_start(cryptoauth_address | I2C_WRITE);
    for (uint8_t x = 0; x < 6; x++) {
      soft_i2c_master_write(data_out[x]);    
    }
    soft_i2c_master_write(crc[0]); 
    soft_i2c_master_write(crc[1]);
    soft_i2c_master_stop();

    delay(70);
    
    sha204a_read_buffer();
    sha204a_idle();

    uint8_t mac[32];
    for (uint8_t x = 0; x < 32; x++) {
      mac[x] = data_in[x+1];
      otp[x] = data_in[x+1];
    }
  }

  incrementNonceCount();
}

void writeData(uint8_t slot, uint8_t* value) {
  sha204a_wakeup();
  
  if (soft_i2c_master_start(cryptoauth_address | I2C_WRITE)) {
    data_out[0] = FUNCTION_COMMAND; // command
    data_out[1] = 7 + 32; // count (included in count)
    data_out[2] = COMMAND_WRITE;
    data_out[3] = ZONE_ENCODING_DATA | READ_32_BYTES;
    data_out[4] = slot << 3;
    data_out[5] = 0;

    for (uint8_t x = 0; x <= 32; x++) {
      data_out[x+6] = value[x];
    }
    
    sha204c_calculate_crc(5 + 32, &data_out[1], crc); // crc starts at count

    soft_i2c_master_start(cryptoauth_address | I2C_WRITE);
    for (uint8_t x = 0; x < 6 + 32; x++) {
      soft_i2c_master_write(data_out[x]);    
    }
    soft_i2c_master_write(crc[0]); 
    soft_i2c_master_write(crc[1]);
    soft_i2c_master_stop();

    delay(50);

    sha204a_read_buffer();
    sha204a_sleep();
  }
}

void sha204a_read_buffer(void) {
  if (soft_i2c_master_start(cryptoauth_address | I2C_READ)) {
    uint8_t x = 0;
    data_in[x] = soft_i2c_master_read(0);
    x++;

    while (x < (data_in[PACKET_COUNT] - 2)) {
      data_in[x] = soft_i2c_master_read(0);
      x++;
    }

    data_in[x] = soft_i2c_master_read(0);
    x++;
    data_in[x] = soft_i2c_master_read(1);
    x++;

    soft_i2c_master_stop();

    // Check CRC matches
    if (sha204c_check_crc(data_in) == false) {
      Serial.println("CRC Failed");
    }
  }
  else {
    Serial.println("not ack addr");
  }
}

void sha204a_read(uint8_t address, uint8_t readCount, uint8_t encodingConfig) {
  data_out[0] = FUNCTION_COMMAND; // command
  data_out[1] = 7; // count (included in count)
  data_out[2] = COMMAND_READ; // read
  data_out[3] = encodingConfig | readCount;
  data_out[4] = address;
  data_out[5] = 0;

  sha204c_calculate_crc(5, &data_out[1], crc); // crc starts at count

  soft_i2c_master_start(cryptoauth_address | I2C_WRITE);
  for (uint8_t x = 0; x < 6; x++) {
    soft_i2c_master_write(data_out[x]);    
  }
  soft_i2c_master_write(crc[0]); 
  soft_i2c_master_write(crc[1]);
  soft_i2c_master_stop();

  delay(4);
}

void sha204c_calculate_crc(uint8_t length, uint8_t *data, uint8_t *crc) {
  uint8_t counter;
  uint16_t crc_register = 0;
  uint16_t polynom = 0x8005;
  uint8_t shift_register;
  uint8_t data_bit, crc_bit;

  for (counter = 0; counter < length; counter++) {
    for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1) {
      data_bit = (data[counter] & shift_register) ? 1 : 0;
      crc_bit = crc_register >> 15;
      crc_register <<= 1;
      if (data_bit != crc_bit)
        crc_register ^= polynom;
    }
  }
  crc[0] = (uint8_t) (crc_register & 0x00FF);
  crc[1] = (uint8_t) (crc_register >> 8);
}

uint8_t sha204c_check_crc(uint8_t *data) {
  uint8_t crc[2];

  uint8_t count = data[PACKET_COUNT];
  sha204c_calculate_crc(count - 2, data, crc);

  if (data[(count-2)] == crc[0] && (data[(count-1)] == crc[1])) {
    return true;
  }
  return false;
}

uint8_t sha204a_wakeup(void) {
  DDRC |= (1<<TWI_SDA_PIN); // Pull-up taken low
  delay(1);
  DDRC &= ~(1<<TWI_SDA_PIN); // Pull-up left high
  delay(3);

  // Read wake packet
  sha204a_read_buffer();
}

uint8_t sha204a_sleep(void) {
  soft_i2c_master_start(cryptoauth_address | I2C_WRITE);
  soft_i2c_master_write(FUNCTION_SLEEP); 
  soft_i2c_master_stop();
} 

uint8_t sha204a_idle(void) {
  soft_i2c_master_start(cryptoauth_address | I2C_WRITE);
  soft_i2c_master_write(FUNCTION_IDLE); 
  soft_i2c_master_stop();
}

// Read a byte from I2C and send Ack if more reads follow else Nak to terminate read
uint8_t soft_i2c_master_read(uint8_t last) {
  uint8_t b = 0;
  for (uint8_t i = 0; i < 8; i++) {
    // Don't change this loop unless you verify the change with a scope
    b <<= 1;
    _delay_loop_1(I2C_DELAY_CYCLES);
    DDRC &= ~(1<<TWI_SCL_PIN);
    _delay_loop_1(I2C_DELAY_CYCLES);
    if (bit_is_set(PINC, TWI_SDA_PIN)) b |= 1;
    _delay_loop_1(I2C_DELAY_CYCLES);
    DDRC |= (1<<TWI_SCL_PIN);
  }
  _delay_loop_1(I2C_DELAY_CYCLES);

  // Send Ack or Nak
  if (last) {
    DDRC &= ~(1<<TWI_SDA_PIN);
  }
  else {
    DDRC |= (1<<TWI_SDA_PIN);
  }

  DDRC &= ~(1<<TWI_SCL_PIN);
  _delay_loop_1(I2C_DELAY_CYCLES);
  DDRC |= (1<<TWI_SCL_PIN);
  DDRC &= ~(1<<TWI_SDA_PIN);

  return b;
}

// Write a byte to I2C
uint8_t soft_i2c_master_write(uint8_t data) {
  uint8_t rtn = 0;

  // Write byte
  for (uint8_t m = 0x80; m != 0; m >>= 1) {
    // Don't change this loop unless you verify the change with a scope
    if (m & data) { 
      DDRC &= ~(1<<TWI_SDA_PIN);
    }
    else { 
      DDRC |= (1<<TWI_SDA_PIN);
    }

    _delay_loop_1(I2C_DELAY_CYCLES);
    DDRC &= ~(1<<TWI_SCL_PIN);
    _delay_loop_1(I2C_DELAY_CYCLES);
    DDRC |= (1<<TWI_SCL_PIN);
    _delay_loop_1(I2C_DELAY_CYCLES);
  }
  _delay_loop_1(I2C_DELAY_CYCLES);

  DDRC &= ~(1<<TWI_SDA_PIN);
  DDRC &= ~(1<<TWI_SCL_PIN);
  _delay_loop_1(I2C_DELAY_CYCLES);

  // get Ack or Nak
  rtn = bit_is_set(PINC, TWI_SDA_PIN);

  DDRC |= (1<<TWI_SCL_PIN);
  DDRC &= ~(1<<TWI_SDA_PIN);
  _delay_loop_1(I2C_DELAY_CYCLES);


  return rtn == 0;
}

// Issue a start condition
uint8_t soft_i2c_master_start(uint8_t addressRW) {
  DDRC |= (1<<TWI_SDA_PIN);
  _delay_loop_1(I2C_DELAY_CYCLES);
  DDRC |= (1<<TWI_SCL_PIN);
  _delay_loop_1(I2C_DELAY_CYCLES);

  return soft_i2c_master_write(addressRW);
}

// Issue a restart condition
uint8_t soft_i2c_master_restart(uint8_t addressRW) {
  DDRC &= ~(1<<TWI_SDA_PIN);
  DDRC &= ~(1<<TWI_SCL_PIN);
  _delay_loop_1(I2C_DELAY_CYCLES);

  return soft_i2c_master_start(addressRW);
}

// Issue a stop condition
void soft_i2c_master_stop(void) {
  DDRC |= (1<<TWI_SDA_PIN);
  _delay_loop_1(I2C_DELAY_CYCLES);

  DDRC &= ~(1<<TWI_SCL_PIN);
  _delay_loop_1(I2C_DELAY_CYCLES);

  DDRC &= ~(1<<TWI_SDA_PIN);
  _delay_loop_1(I2C_DELAY_CYCLES);
}
