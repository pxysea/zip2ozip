# zip2ozip

# 使用方法：  
## 压缩  
  `cd c:\OPPO\PACM00_11_2270`  
  `"C:\Program Files\7-Zip\7z.exe" a -r -aoa ..\PACM00_11_2270.zip *.*`  

  `c:\OPPO\zip2ozip\zip2ozip.exe c:\OPPO\PACM00_11_2270.zip c:\OPPO\config.txt`
###  下一步：签名 ozip 文件
  ### 签名方法 网上查找
  ### 上传到手机
  `adb push c:\OPPO\PACM00_11_2270.ozip /sdcard/Download/`  
  `adb reboot recovery`  

# 其他方法：
## 查看签名信息
  `keytool -printcert -jarfile PACM00_11_2270.zip`
  
# 引用
`https://github.com/affggh/oppo_ozip_encrypt`
