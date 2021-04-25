CpPhyDummySlave: Baudrate = 19200
DPM1: Trying to initialize slave 42...
CpPhyDummySlave: Sending SRD  10 2A 02 49 75 16
CpPhyDummySlave: Receiving    10 02 2A 00 2C 16
DPM1: slave[2A].state --> 'wait for diag'
DPM1: Requesting Slave_Diag from slave 42...
CpPhyDummySlave: Sending SRD  68 05 05 68 AA 82 6D 3C 3E 13 16
CpPhyDummySlave: Receiving    A2 82 AA 08 3E 3C 00 00 00 FF 00 00 AD 16
DPM1: slave[2A].state --> 'wait for Prm'    
DPM1: Sending Set_Prm to slave 42...
CpPhyDummySlave: Sending SRD  68 10 10 68 AA 82 5D 3D 3E B8 1E 01 00 42 24 01 00 00 00 42 84 16
CpPhyDummySlave: Receiving    E5
DPM1: slave[2A].state --> 'wait for Cfg'
CpPhyDummySlave: Sending SRD  68 09 09 68 AA 82 7D 3E 3E 00 20 20 10 75 16
CpPhyDummySlave: Receiving    E5
DPM1: slave[2A].state --> 'wait for Data_Exchange-ready'
DPM1: Requesting Slave_Diag (WDXRDY) from slave 42...
CpPhyDummySlave: Sending SRD  68 05 05 68 AA 82 5D 3C 3E 03 16
CpPhyDummySlave: Receiving    A2 82 AA 08 3E 3C 00 00 00 FF 00 00 AD 16
DPM1: Slave 42 diagnostic always-one-bit is zero.
DPM1: slave[2A].state --> 'Data_Exchange'
DPM1: Initialization finished. Running Data_Exchange with slave 42...
CpPhyDummySlave: Sending SRD  68 05 05 68 2A 02 7D 42 24 0F 16
CpPhyDummySlave: Receiving    68 05 05 68 02 2A 08 BD DB CC 16
CpPhyDummySlave: Sending SRD  68 05 05 68 2A 02 5D DB BD 21 16
CpPhyDummySlave: Receiving    68 05 05 68 02 2A 08 24 42 9A 16
CpPhyDummySlave: Sending SRD  68 05 05 68 2A 02 7D 42 24 0F 16
CpPhyDummySlave: Receiving    68 05 05 68 02 2A 08 BD DB CC 16
