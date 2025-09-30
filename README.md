# csaw_ai_hardware_challenge_1_easy
## CSAW Challenge 1 Easy Writeup

I tackled the easy tier by partnering with GitHub Copilot Chat (GPT-5-Codex (Preview) Model) in Agent Mode directly inside VS Code. I kept a running conversation where I asked for code edits, diff reviews, and simulation commands. Copilot generated the RTL changes plus the custom testbench while the agent itself analysed the errors and solved them. There were no extra wrappers or scripts involved. It took a while to get to the actual working solution by going through 2-3 methods. The actual AI model underneath was the GPT-5-Codex that OpenAI currently has in Preview, invoked through the VS Code sidebar.

## What the Trojan Does

The Trojan lives in `rtl/aes.v` and quietly hijacks the status register. Every time the AES core finishes processing a block it pushes the next byte of the expanded key into the upper eight bits of the status word. The logic tracks whether the key is 128 or 256 bits so it knows when to wrap back to the start. The rest of the status register still advertises `ready` and `valid` just like the original design. Because the byte stream shows up one block at a time, normal traffic keeps the leak flowing without suspicious handshakes or extra pins. After enough encrypt operations an observer that performs ordinary status reads can reconstruct the entire key.

## How to Test It

1. Build the original regression suite:
   ```powershell
   cd C:\Users\sgpan\CSAW-AI-Hardware-Attack-Challenge\challenges\challenge_1\01_easy
   iverilog -g2012 -o build_tb_aes.vvp tb\tb_aes.v rtl\aes.v rtl\aes_core.v rtl\aes_encipher_block.v rtl\aes_decipher_block.v rtl\aes_sbox.v rtl\aes_inv_sbox.v rtl\aes_key_mem.v
   vvp build_tb_aes.vvp
   ```
   That run proves the modified core still matches all NIST vectors.

2. Build and run the Trojan demo bench:
   ```powershell
   iverilog -g2012 -o build_tb_aes_trojan.vvp tb\tb_aes_trojan.v rtl\aes.v rtl\aes_core.v rtl\aes_encipher_block.v rtl\aes_decipher_block.v rtl\aes_sbox.v rtl\aes_inv_sbox.v rtl\aes_key_mem.v
   vvp build_tb_aes_trojan.vvp
   ```
   The script prints the leaked byte stream followed by the recovered AES key. For the sample run it reconstructs `0x2b7e151628aed2a6abf7158809cf4f3c`, which matches the secret loaded at the start of the bench.

That is all that was required to solve the easy challenge: subtle key leakage, no disruption to functional testing, and a simple proof that the Trojan works in simulation.
