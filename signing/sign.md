To sign your own files you need to create an authorized certificate first.

Download windows SDK signing tools, run cmd as adminstrator, execute this and fill <YOUR_PASSWORD> with your password and <FILE_PATH> with the file's path:

```
cd C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64
makecert -sky signature -r -n "CN=RootCert" -pe -a sha256 -len 2048 -ss MY -cy authority -sv RootCert.pvk RootCert.cer
makecert -pe -n "CN=CodeSignCert" -ss my -sr LocalMachine -a sha256 -sky signature -cy end -ic RootCert.cer -iv RootCert.pvk -sv CodeSignCert.pvk CodeSignCert.cer
pvk2pfx -pvk CodeSignCert.pvk -spc CodeSignCert.cer -pfx CodeSignCert.pfx -po <YOUR_PASSWORD>
signtool sign /f CodeSignCert.pfx /fd SHA256 /p <YOUR_PASSWORD> /t http://timestamp.digicert.com <FILE_PATH>
```
Then import this unauthorized certificate to the authorized certificates file by 

WIN+R, MMC, FILE, ADD SNAP-IN, ADD CERTIFICATES, Right Click on Authorized CAs, All tasks, import, choose RootCert.cer.

Now the file is signed by the authorized certificate!
