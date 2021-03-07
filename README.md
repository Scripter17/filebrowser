# FileBrowser
A Node.js webserver to let you remotely access parts of your computer's filesystem

**NOTE: This has not been properly pentested. I have put considerable effort into making sure it's safe and secure, but I make no guarentees**

---

FileBrowser is a project I've been working on for a few years now. It's gone through several iterations and rebuilds but this is its current form. FileBrowser is a Node.js script that creates a webserver primarily so you can access files from your computer on your phone/3ds/whatnot. I admit, this was orginally built for porn. Howver, I've built upon it to the point of it becoming a genuinly useful tool in day-to-day life beyond that.

---

## Config.json

Before you can properly use FileBrowser, you need to set up config.json. This manages all accounts, what they can/can't access, and whether or not they can upload files

### Initial Config.json

```JSON
{
	"redirs":{},
	"accounts":{
		"admin":{
			"passHash":"",
			"allow":[],
			"deny":[],
			"canUpload":false
		}
	},
	"viewSettings":{
		"folder":{
			"imageMode":"link",
			"videoMode":"link"
		}
	},
	"defaultUploadLoc":"./files/",
	"hashType":"sha256",
	"hashSalt":"",
	"useHTTPS":false,
	"httpsKey":"key.pem",
	"httpsCert":"cert.pem",
	"maxFileSize":"8MiB"
}
```

Todo: Proper documentation

# License

This project is released under the ["Don't Be a Dick"](https://dbad-license.org) public license. From my limited research this is compatible with both the MIT and GPL licenses which some packages I use are released under. If it isn't compatible then I will go so far as not using Express.js, because I *will not* release this under anything other than the DBaD PL