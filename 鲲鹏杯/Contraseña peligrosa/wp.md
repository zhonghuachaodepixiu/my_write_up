# Contraseña peligrosa

## flag:``flag{admin123}``
### 解题人：种花草的貔貅

题目给我们一个文件，用记事本打开后得到一串字符：
```text
3d3d77626c414349787043647a465349786479646773534a785243496d637964335a534932523349674d43636841434a686343636e51694b306c57647a354864
```

可以很轻松的判断出来这是十六进制，用**CyberChef**解码后得到：
```text
==wblACIxpCdzFSIxdydgsSJxRCImcyd3ZSI2R3IgMCchACJhcCcnQiK0lWdz5Hd
```

看到两个`=`在最前面，合理怀疑是一串倒置的`base64`编码，用脚本倒转一下，得到：
```text
dH5zdWl0KiQncCchJCAhcCMgI3R2ISZ3dycmICRxJSsgdydxISFzdCpxICAlbw==
```

然后用**CyberChef**的`Magic`模块，解出来一串疑似flag的东西：
```text
flag{f865b53623b121fd34ee5426c792e5c33af8c227}
```

这个并不是flag，~~因为我交了一次~~由题面的西班牙语可以得知，这个明面上的答案是错的。

仔细观察，发现中间部分和哈希值很像，尝试用`cmd5.com`还原。

发现这个是`sha1`，得到`admin123`，放入flag{}中提交，发现已通过