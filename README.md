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

# 其他：
# 头部信息
  ![image](https://github.com/pxysea/zip2ozip/assets/3711185/1e7d2f3f-53dd-4884-95fe-23676ba2f59a)
# 数据开始 0x1050h

# 查看签名信息
  `keytool -printcert -jarfile PACM00_11_2270.zip`
  
# 引用
`https://github.com/affggh/oppo_ozip_encrypt`

