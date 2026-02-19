# Pinouts/Connections of my PCB

STM32H732VG pin name <-> stm32 pin nr <-> Function (Impedance match/strap) <-> Switch Pin

PC1 16 ETH_MDC 36
PA1 23 ETH_REF_CLK (50ohm) 26
PA2 24 ETH_MDIO (4.7k Pullup) 
PA7 31 ETH_RX_DV (50ohm)  
PC4 32 ETH_RXD0 (50ohm)
PC5 33 ETH_RXD1 (50ohm)
PB11 47 ETH_TX_EN (50ohm)
PB12 51 ETH_TXD0 (50ohm)
PB13 52 ETH_TXD1 (50ohm)


Other switch pins
6 11.8k Pulldown
17 10k Pullup
47 10k Pullup + 10uF Cap to GND
LEDS all pull up/high
