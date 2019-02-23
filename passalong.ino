/*
 ATSHA204A I2C Examples
 Version: 1.0
 Author: Alex from insideGadgets (http://www.insidegadgets.com)
 Created: 21/04/2017
 Last Modified: 21/04/2017
 
 Open serial monitor at 9600 to access the ATSHA204A commands such as:
 "test" - Tests to see if waking up the device works
 "read" - Print out the configuration zone
 "write" - Write 4 bytes to slot config 0 & 1 in the configuration zone
 "rand" - Return a 32 byte random number, it's only random if the configuration zone is locked
 "lockconfig" - Lock the configuration zone. *Be careful, once locked, it can't be unlocked*
 "lockdata" - Lock the data and OTP zones. *Be careful, once locked, it can't be unlocked*
 "loadkey" - Write a 32 byte number in slot 0, this will be our secret key. *You should change the number*
 "nonce" - Use the pass through mode to load a 32 byte number into TempKey
 "hmac" - Combines the nonce with slot 0 key to generate the HMAC result
 
 */

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
#define COMMAND_HMAC 0x11
#define COMMAND_NONCE 0x16
#define COMMAND_RANDOM 0x1B
#define COMMAND_LOCK 0x17

#define ZONE_ENCODING_CONFIG 0
#define ZONE_ENCODING_OTP 1
#define ZONE_ENCODING_DATA 2

#define ZONE_LOCK_CONFIG 0
#define ZONE_LOCK_DATA_OTP 1

#define NONCE_PASS_THROUGH 0x03

#define READ_4_BYTES 0x00
#define READ_32_BYTES 0x80

#define LOCK_NO_CRC_CHECK 0x80

#define KEY_SLOT 0
#define NONCE_COUNT_SLOT 0x08

uint8_t data_out[40];
uint8_t data_in[35];
uint8_t crc[2];

uint8_t counter = 0;


void printBase64(uint8_t* bytes, uint8_t len) {
    char base64[64];
    encode_base64(bytes, len, base64);
    Serial.println((char*)base64);
}

void setup() {
  Serial.begin(9600);

  // Initialse I2C
  DDRC &= ~(1<<TWI_SCL_PIN);
  PORTC &= ~(1<<TWI_SCL_PIN);
  DDRC &= ~(1<<TWI_SDA_PIN);
  PORTC &= ~(1<<TWI_SDA_PIN);
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

void generateRandomNumber(uint8_t* data) {
  sha204a_wakeup();

  if (soft_i2c_master_start(cryptoauth_address | I2C_WRITE)) {
    data_out[0] = FUNCTION_COMMAND; // command
    data_out[1] = 7; // count (included in count)
    data_out[2] = COMMAND_RANDOM;
    data_out[3] = 0;
    data_out[4] = 0;
    data_out[5] = 0;

    sha204c_calculate_crc(5, &data_out[1], crc); // crc starts at count

    soft_i2c_master_start(cryptoauth_address | I2C_WRITE);
    for (uint8_t x = 0; x < 6; x++) {
      soft_i2c_master_write(data_out[x]);    
    }
    soft_i2c_master_write(crc[0]); 
    soft_i2c_master_write(crc[1]);
    soft_i2c_master_stop();

    delay(50);

    sha204a_read_buffer();
    sha204a_sleep();

    for (uint8_t x = 0; x < 32; x++) {
      data[x] = data_in[x+1];
    }
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

void loadNonce() {
  uint8_t nonceData[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  uint32_t count = getNonceCount(nonceData);
  printBase64(nonceData, 32);
  Serial.println(count);
  
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

void loop() {
  // Wait for serial input
  while (Serial.available() <= 0) {
    delay(200);
  }

  // Decode input
  char readInput[10];
  int readCount = 0;
  while (Serial.available() > 0) {
    char c = Serial.read();
    readInput[readCount] = c;
    readCount++;
  }
  readInput[readCount] = '\0';

  // Test to see if the device wakes up
  if (strstr(readInput, "wake")) {
    sha204a_wakeup();
    sha204a_sleep();
  }
  

  // Read config zone
  else if (strstr(readInput, "read")) {
    sha204a_print_config();
  }

  // Write slot config 0
  else if (strstr(readInput, "write")) {
    sha204a_wakeup();

    data_out[0] = FUNCTION_COMMAND; // command
    data_out[1] = 9 + 2; // count (included in count + crc (add 2))
    data_out[2] = COMMAND_WRITE;
    data_out[3] = ZONE_ENCODING_CONFIG;
    data_out[4] = 5;
    data_out[5] = 0;

    data_out[6] = 0x80;
    data_out[7] = 0x80;
    data_out[8] = 0x80;
    data_out[9] = 0xA1;

    sha204c_calculate_crc(9, &data_out[1], crc); // crc starts at count

    soft_i2c_master_start(cryptoauth_address | I2C_WRITE);
    for (uint8_t x = 0; x < 10; x++) {
      soft_i2c_master_write(data_out[x]);
    }
    soft_i2c_master_write(crc[0]); 
    soft_i2c_master_write(crc[1]);

    soft_i2c_master_stop();

    delay(50);

    sha204a_read_buffer();
    sha204a_sleep();
  }

  // Read random number
  else if (strstr(readInput, "rand")) {
    uint8_t rand[32];
    generateRandomNumber(rand);
    //printBase64(rand, 32);
  }

  // Lock configuration
  else if (strstr(readInput, "lockconfig")) {
    sha204a_print_config();
    
    Serial.println("\nGoing to lock configuration zone, are you sure? y/n");

    // Wait for serial input
    while (Serial.available() <= 0) {
      delay(50);
    }

    // Decode input
    readCount = 0;
    while (Serial.available() > 0) {
      char c = Serial.read();
      readInput[readCount] = c;
      readCount++;
    }
    readInput[readCount] = '\0';

    // Yes
    if (strstr(readInput, "y")) {
      sha204a_wakeup();
      
      if (soft_i2c_master_start(cryptoauth_address | I2C_WRITE)) {
       data_out[0] = FUNCTION_COMMAND; // command
       data_out[1] = 7; // count (included in count)
       data_out[2] = COMMAND_LOCK;
       data_out[3] = ZONE_LOCK_CONFIG | LOCK_NO_CRC_CHECK;
       data_out[4] = 0;
       data_out[5] = 0;
       
       sha204c_calculate_crc(5, &data_out[1], crc); // crc starts at count
       
       soft_i2c_master_start(cryptoauth_address | I2C_WRITE);
       for (uint8_t x = 0; x < 6; x++) {
         soft_i2c_master_write(data_out[x]);    
       }
       soft_i2c_master_write(crc[0]); 
       soft_i2c_master_write(crc[1]);
       soft_i2c_master_stop();
       
       delay(30);
       
       sha204a_read_buffer();
       sha204a_sleep();
      }
      else {
        Serial.println("not ack addr");
      }
    }
    else {
      Serial.println("Aborted");
    }
  }

  // Lock data / otp
  else if (strstr(readInput, "lockdata")) {
    Serial.println("\nGoing to lock data and otp zones, are you sure? y/n");

    // Wait for serial input
    while (Serial.available() <= 0) {
      delay(50);
    }

    // Decode input
    readCount = 0;
    while (Serial.available() > 0) {
      char c = Serial.read();
      readInput[readCount] = c;
      readCount++;
    }
    readInput[readCount] = '\0';

    // Yes
    if (strstr(readInput, "y")) {
      sha204a_wakeup();
      
      if (soft_i2c_master_start(cryptoauth_address | I2C_WRITE)) {
       data_out[0] = FUNCTION_COMMAND; // command
       data_out[1] = 7; // count (included in count)
       data_out[2] = COMMAND_LOCK;
       data_out[3] = ZONE_LOCK_DATA_OTP | LOCK_NO_CRC_CHECK;
       data_out[4] = 0;
       data_out[5] = 0;
       
       sha204c_calculate_crc(5, &data_out[1], crc); // crc starts at count
       
       soft_i2c_master_start(cryptoauth_address | I2C_WRITE);
       for (uint8_t x = 0; x < 6; x++) {
         soft_i2c_master_write(data_out[x]);    
       }
       soft_i2c_master_write(crc[0]); 
       soft_i2c_master_write(crc[1]);
       soft_i2c_master_stop();
       
       delay(30);
       
       sha204a_read_buffer();
       sha204a_sleep();
      }
      else {
        Serial.println("not ack addr");
      }
    }
    else {
      Serial.println("Aborted");
    }
  }

  // Write data key to slot 0
  else if (strstr(readInput, "loadkeys")) {
    uint8_t privkey[32];
    for (int i = 0; i < 16; i++) {
      generateRandomNumber(privkey);
      writeData(i, privkey);
      Serial.println(i);
      printBase64(privkey, 32);
    }
  }
  
  // Nonce to load 32 byte random number
  else if (strstr(readInput, "nonce")) {
    loadNonce();
  }
  
  // MAC the challenge with the key
  else if (strstr(readInput, "mac")) {
    loadNonce();

    sha204a_wakeup();
    
    if (soft_i2c_master_start(cryptoauth_address | I2C_WRITE)) {
      data_out[0] = FUNCTION_COMMAND; // command
      data_out[1] = 7; // count (included in count)
      data_out[2] = 0x08;//COMMAND_HMAC;
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
      }
      printBase64(mac, 32);
    }

    incrementNonceCount();
  }
}

void sha204a_read_buffer(void) {
  if (soft_i2c_master_start(cryptoauth_address | I2C_READ)) {
    uint8_t x = 0;
    data_in[x] = soft_i2c_master_read(0);
    Serial.print("Count = 0x");
    if (data_in[x] <= 0x0F) {
      Serial.print("0");
    }
    Serial.print(data_in[PACKET_COUNT], HEX);
    Serial.print(", ");
    x++;

    Serial.print("Data = ");
    while (x < (data_in[PACKET_COUNT] - 2)) {
      data_in[x] = soft_i2c_master_read(0);
      Serial.print("0x");
      if (data_in[x] <= 0x0F) {
      Serial.print("0");
    }
      Serial.print(data_in[x], HEX);
      Serial.print(", ");
      x++;
    }

    Serial.print(", CRC = ");
    data_in[x] = soft_i2c_master_read(0);
    Serial.print("0x");
    if (data_in[x] <= 0x0F) {
      Serial.print("0");
    }
    Serial.print(data_in[x], HEX);
    Serial.print(", ");
    x++;
    data_in[x] = soft_i2c_master_read(1);
    Serial.print("0x");
    if (data_in[x] <= 0x0F) {
      Serial.print("0");
    }
    Serial.print(data_in[x], HEX);
    Serial.print(" ");
    x++;

    soft_i2c_master_stop();

    // Check CRC matches
    if (sha204c_check_crc(data_in) == true) {
      Serial.println("CRC Ok");
    }
    else {
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

uint8_t sha204a_print_config(void) {
  uint8_t configBytes[88];

  sha204a_wakeup();
  sha204a_read(0, READ_32_BYTES, ZONE_ENCODING_CONFIG);
  sha204a_read_buffer();
  sha204a_sleep();

  for (uint8_t x = 0; x < 32; x++) {
    configBytes[x] = data_in[x+1];
  }

  sha204a_wakeup();
  sha204a_read(0x8, READ_32_BYTES, ZONE_ENCODING_CONFIG);
  sha204a_read_buffer();
  sha204a_sleep();
  
  for (uint8_t x = 0; x < 32; x++) {
    configBytes[x+32] = data_in[x+1];
  }

  sha204a_wakeup();
  sha204a_read(0x10, READ_4_BYTES, ZONE_ENCODING_CONFIG);
  sha204a_read_buffer();
  sha204a_sleep();
  
  for (uint8_t x = 0; x < 4; x++) {
    configBytes[x+64] = data_in[x+1];
  }

  sha204a_wakeup();
  sha204a_read(0x11, READ_4_BYTES, ZONE_ENCODING_CONFIG);
  sha204a_read_buffer();
  sha204a_sleep();
  
  for (uint8_t x = 0; x < 4; x++) {
    configBytes[x+68] = data_in[x+1];
  }

  sha204a_wakeup();
  sha204a_read(0x12, READ_4_BYTES, ZONE_ENCODING_CONFIG);
  sha204a_read_buffer();
  sha204a_sleep();
  
  for (uint8_t x = 0; x < 4; x++) {
    configBytes[x+72] = data_in[x+1];
  }

  sha204a_wakeup();
  sha204a_read(0x13, READ_4_BYTES, ZONE_ENCODING_CONFIG);
  sha204a_read_buffer();
  sha204a_sleep();
  
  for (uint8_t x = 0; x < 4; x++) {
    configBytes[x+76] = data_in[x+1];
  }

  sha204a_wakeup();
  sha204a_read(0x14, READ_4_BYTES, ZONE_ENCODING_CONFIG);
  sha204a_read_buffer();
  sha204a_sleep();
  
  for (uint8_t x = 0; x < 4; x++) {
    configBytes[x+80] = data_in[x+1];
  }

  sha204a_wakeup();
  sha204a_read(0x15, READ_4_BYTES, ZONE_ENCODING_CONFIG);
  sha204a_read_buffer();
  sha204a_sleep();
  
  for (uint8_t x = 0; x < 4; x++) {
    configBytes[x+84] = data_in[x+1];
  }
  
  
  Serial.println(" ");
  Serial.println("Configuration Zone");
  uint8_t printbreak = 3;
  for (uint8_t x = 0; x < 88; x++) {
    if (configBytes[x] <= 0x0F) {
      Serial.print("0");
    }
    Serial.print(configBytes[x], HEX);
    Serial.print(" ");
    if (x == printbreak) {
      Serial.println(" ");
      printbreak += 4;
    }
  }

  Serial.print("\nSlot Config\n");
  for (uint8_t i = 0; i < 16; i++) {
    print_config_slot(configBytes, i);
  }

  
}

void print_hex(uint8_t value) {
  if (value <= 0x0F) {
    Serial.print("0");
  }
  Serial.print(value, HEX);
}

void print_bin(uint8_t value, uint8_t max_value) {
  if (max_value > 64 && value < 64) {
    Serial.print("0");
  }
  if (max_value > 32 && value < 32) {
    Serial.print("0");
  }
  if (max_value > 16 && value < 16) {
    Serial.print("0");
  }
  if (max_value > 8 && value < 8) {
    Serial.print("0");
  }
  if (max_value > 4 && value < 4) {
    Serial.print("0");
  }
  if (max_value > 2 && value < 2) {
    Serial.print("0");
  }
  Serial.print(value, BIN);
}

void print_config_slot(uint8_t *configBytes, uint8_t slot) {
  if (slot < 10) {
    Serial.print(" ");
  }
  Serial.print(slot);
  Serial.print(" (");
  
  uint8_t slot_begin = 20 + 2 * slot;

  print_hex(configBytes[slot_begin]);
  Serial.print(" ");
  
  print_hex(configBytes[slot_begin + 1]);
  Serial.print("): ");

  print_bin(configBytes[slot_begin] >> 4, 16);
  Serial.print(" ");

  uint8_t write_key = configBytes[slot_begin] & 0x0F;
  if (write_key < 10) {
    Serial.print(" ");
  }
  Serial.print(write_key);
  Serial.print(" ");
  
  if ((1 << 7) & configBytes[slot_begin + 1]) {
    Serial.print("S");
  } else {
    Serial.print("s");
  }

  if ((1 << 6) & configBytes[slot_begin + 1]) {
    Serial.print("E");
  } else {
    Serial.print("e");
  }

  if ((1 << 5) & configBytes[slot_begin + 1]) {
    Serial.print("L");
  } else {
    Serial.print("l");
  }

  if ((1 << 4) & configBytes[slot_begin + 1]) {
    Serial.print("C");
  } else {
    Serial.print("c");
  }

  Serial.print(" ");

  uint8_t read_key = configBytes[slot_begin + 1] & 0x0F;
  if (read_key < 10) {
    Serial.print(" ");
  }
  Serial.print(read_key);
  Serial.print(" ");

  Serial.println();
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
