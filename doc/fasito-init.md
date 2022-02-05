# Init Fasito

### First load the firmware onto the device:
The Fasito.hex firmware file can be built from the [Fasito](https://github.com/faircoin/Fasito) repository. Flasher software is available here: [teensy_loader_cli](https://github.com/faircoin/teensy_loader_cli)
```
./teensy_loader_cli --mcu=FASITO -v -w Fasito.hex
```

### Start minicom and make sure you can access the device
```
minicom -D /dev/ttyACM0
```
Press `Ctrl+a` and the key `e` afterwards to activate local ECHOs. Otherwise you won't get any feedback while you're typing intil you press `<enter>`.

Type `INFO` or `HELP` to test if the Fasito firmware responds.

Now we need to INITialize the Fasito with some keys. Four keys are needed:
1. A admin public key
2. One more admin public key
3. A third admin public key
4. A device manager private key

The admin public keys are needed to `UNSEAL` the fasito or to reset the PIN. So keep those keys safe! It's a good idea to distribute the keys to one or two trusted people. If you create several Fasitos you can reuse the admin keys for all of the Fasitos. But! The device manager private key has to be unique for each Fasito device! It replaces an absent random number generator on the device.

If the admin public keys are lost the Fasito can't be reconfigured at all.

### General syntax of INIT command
```
INIT <PIN> <admin pub key #1> <admin pub key #2> <admin pub key #3> <device manager private key>
```

For example:
```
INIT 123456 04023ae86ff78e3e4bb8d565758484989df7e4ebe5c7bb7ee512f6ed009f0e74b5fd3e44b756be26507f3dbfb487ca0c2ee9276d7b889905e7f1be7c1fd6ba7bd6 04482308ca58c08c4934c65ec6ee3ed5ee49d3cb10f1f486beaf791640246d233a36b40bb96ea1ec519bcefbef9135ac4f89516e6181d66350c92d8acc9b38a63c 048e21294253810a8292b4560d3fb2288786db72e2a286eee5151590eb44de6297aa64b8befc180615e0b047f4ce107d94683b696a18895a35e8bce9a9f0c8d899 b2b4f0a8c234ade4ddee088b4341d25016a4c5bd8662949431cf8570e4ff1d25
```

### Helper script
Available at [key creation script](https://raw.githubusercontent.com/faircoin/Fasito/master/handling/createInitKeys.sh)

This script creates three EC key pairs and outputs a possible INIT command.

After download of key creation script make sure it's executable:
`chmod +x createInitKeys.sh`

### Create the keys and a sample INIT command
`./createInitKeys.sh`

### In minicom now initialise the token.
If the keys and the suggested PIN suits you. Just paste the command with all five parameters into the minicom window.

At the end the `INFO` command should return something like this:
```
Fasito version    : v1.3
Serial number     : <snip>
Token status      : CONFIGURED
Protection status : 0x11011110 (0xde), AUTH-Requests: 0
Config version    : 1
Config checksum   : 7302
Nonce pool size   : 25

User PIN          : SET (tries left: 3)

Key #0            : 0x00000000 (SEEDED)
Key #1            : 0x00000000 (SEEDED)
Key #2            : 0x00000000 (SEEDED)
Key #3            : 0x00000000 (SEEDED)
Key #4            : 0x00000000 (SEEDED)
Key #5            : 0x00000000 (SEEDED)
Key #6            : 0x00000000 (SEEDED)
Key #7            : 0x00000000 (CONFIGURED, protected)
```

### Finally, seal the fasito before sending it to the CVN host:
`SEAL`
