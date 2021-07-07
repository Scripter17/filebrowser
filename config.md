# Config.json setup

Before you can properly use Nasifier, you need to set up config.json. This manages all accounts, what they can/can't access, and whether or not they can upload files

### Initial Config.json

```JSON
{
	"redirects":{},
	"accounts":{
		"admin":{
			"passHash":"",
			"allow":[],
			"allowGlob":[],
			"deny":[],
			"denyGlob":[],
			"canUpload":false,
			"viewSettings":{
				"folder":{
					"imageMode":"thumbnail"
				}
			}
		}
	},
	"viewSettings":{
		"cacheViews":true,
		"folder":{
			"imageMode":"link",
			"imageRegex":"\\.(a?png|j(pe?g|fif)|gif|bmp)$",
			"videoMode":"link",
			"videoRegex":"\\.(mp4|mov|webm|mkv)$",
			"handleLNKFiles":true,
			"handleAtFiles":true
		}
	},
	"defaultUploadLoc":"./files",
	"hashType":"sha256",
	"hashSalt":"Jf*4j7'D^{+rV;/N$y73",
	"useHTTPS":false,
	"httpsKey":"key.pem",
	"httpsCert":"cert.pem",
	"httpPort":80,
	"httpsPort":443,
	"maxFileSize":"50MiB",
	"basePath":""
}
```

# Option documentation

TODO