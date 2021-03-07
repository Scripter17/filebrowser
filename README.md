# FileBrowser
A Node.js webserver to let you remotely access parts of your computer's filesystem

**NOTE: This has not been properly pentested. I have put considerable effort into making sure it's safe and secure, but I make no guarentees**

---

FileBrowser is a project I've been working on for a few years now. It's gone through several iterations and rebuilds but this is its current form. FileBrowser is a Node.js script that creates a webserver primarily so you can access files from your computer on your phone/3ds/whatnot. I admit, this was orginally built for porn. However, I've built upon it to the point of it becoming a genuinly useful tool in day-to-day life beyond that.

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

## Config documentation
- `redirs[shortName]="/C:/Path/To/Long/Path"`: Can also be used to link to other websites
- `accounts[account]`: Per-account configuration. (`account` is the username used for logging in)
- `accounts[account].passHash`: The salted hash for `account`
- `accounts[account].allow`: An array of files/folders the user can access. a blank string (`""`) allows for all files/folders and is almost always a bad idea
- `accounts[account].deny`: An array of files/folders inside of folders listed in `accounts[account].allow` to explicitly deny
- `accounts[account].canUpload`: Either `true` to allow uploading to `defaultUploadLoc` or a string to specify a per-user upload location. Should be kept as `false` for accounts other than the admin one
- `viewSettings.folder.imageMode`: Either `"link"`, `"embed"`, or `"thumbnail"`. Works as expected (thumbnails are at most 512x512 and much less resource/network intenseive than `embed`)
- `viewSettings.folder.videoMode`: Either `"link"` or `"embed"`. Works the same as `viewSettings.folder.imageMode` except for videos
- `defaultUplodLoc`: The default path for uploaded files to be placed into. Can be overriden on a per-user basis in `accounts[account].canUpload`
- `hashType`: Any hash name that Node's crpyto package can handle
- `hashSalt`: A (preferably long) string of characters to help defend against dictionary attacks if the config file or a `accounts[account].passHash` is ever leaked
- `useHTTPS`: It, well, it enabled HTTPS when `true`
- `httpsKey`: The path to an HTTPS key (only tested with .pem files)
- `httpsCery`: The path to an HTTPS cert (only tested with .pem files)
- `maxFileSize`: Either `-1` for infinite or a number followed by `"B"`, `"KB"`, `"KiB"`, `"MB"`, `"MiB"`, `"GB"`, or `"GiB"`

# License

This project is released under the ["Don't Be a Dick"](https://dbad-license.org) public license. From my limited research this is compatible with both the MIT and GPL licenses which some packages I use are released under. If it isn't compatible then I will go so far as not using Express.js, because I *will not* release this under anything other than the DBaD PL