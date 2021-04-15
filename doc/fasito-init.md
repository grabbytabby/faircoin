# Init Fasito

### First load the firmware onto the device:
Flasher software is available here: [teensy_loader_cli](https://github.com/faircoin/teensy_loader_cli)
```
./teensy_loader_cli --mcu=FASITO -v -w Fasito.hex
```

### Start minicom and make sure you can access the device
```
minicom -D /dev/ttyACM0
```
Type `INFO` or `HELP` to test it. (Note: you will not get any feedback while you're typing until you press `<enter>`)

### Create helper script
This script creats a new EC key pair and outputs the private and public parts.
```
cat >./createDeviceAdminKey.sh << EOF
#!/bin/bash

openssl req -new -x509 -nodes -newkey ec:<(openssl ecparam -name secp256k1) -keyout tmpKey.key \
 -days 3650 -subj "/O=key" -out tmpKey.crt 2>/dev/null

openssl ec -in tmpKey.key -outform DER 2>/dev/null | xxd -p -c 180 | cut -c 15-78
openssl ec -in tmpKey.key -pubout -outform DER 2>/dev/null | xxd -p -c 180 | cut -c 47-

rm tmpKey.key tmpKey.crt
EOF
chmod +x ./createDeviceAdminKey.sh
```

### Create device-recovery private key:
`./createDeviceAdminKey.sh`

### In minicom now initialise the token.
```
Syntax: INIT <PIN> <admin pub key #1> <admin pub key #2> <admin pub key #3> <device manager private key> 
```

For example: 
```
INIT 123456 04023ae86ff78e3e4bb8d565758484989df7e4ebe5c7bb7ee512f6ed009f0e74b5fd3e44b756be26507f3dbfb487ca0c2ee9276d7b889905e7f1be7c1fd6ba7bd6 04482308ca58c08c4934c65ec6ee3ed5ee49d3cb10f1f486beaf791640246d233a36b40bb96ea1ec519bcefbef9135ac4f89516e6181d66350c92d8acc9b38a63c 048e21294253810a8292b4560d3fb2288786db72e2a286eee5151590eb44de6297aa64b8befc180615e0b047f4ce107d94683b696a18895a35e8bce9a9f0c8d899 b2b4f0a8c234ade4ddee088b4341d25016a4c5bd8662949431cf8570e4ff1d25
```

### Finally, seal the fasito before sending it to the CVN host:
`SEAL`
