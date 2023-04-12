Mark Case

To Create User:

1. Run server by copying Client folder into the Server dist
2. Run cmd inside Server dist
3. Copy this line in and run: java -jar Server.jar -c Config/config.json

4. Copy both ClientConfig and hosts.json into the Client dist
5. Run cmd inside Client dist
6. Copy this line in and run (You may change username if you wish): java -jar Client.jar -h hosts.json -u alice -s create
7. Create a password for your account
8. Copy the Base32 key recievced back and enter it into this website: https://freeotp.github.io/qrcode.html 
	- Change the hash to sha-1
	- Change timer to timeout
	- Make sure timelimit is 30 seconds
	- Give your account a name
	- Remove the random base32 key and enter yours
	- Scan the QR code using any otp app such as google authenticator
9. Restart Server by Ctrl-C
10. Done


To authenticate a user:

Perform this if your you have your server down
	- Run cmd inside Server dist
	- Copy this line in and run: java -jar Server.jar -c Config/config.json
If server still up from creating a user, run this
	- Copy this line in and run: java -jar Server.jar -c Config/config.json

1. Run this line with -u being the user you want to authenticate: java -jar Client.jar -h hosts.json -u newme -s authenticate
2. Enter your password
3. Enter your totp
4. Done