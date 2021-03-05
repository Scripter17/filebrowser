# FileBrowser
 A webserver to let you remotely access parts of your computer's filesystem

**NOTE: This has not been properly pentested. I have put considerable effort into making sure it's safe and secure, but I make no guarentees**

---

FileBrowser is a project I've been working on for a few years now. It's gone through a few iterations and rebuilds but this is its current form. FileBrowser is a Node.js script that creates a webserver primarily so you can access files from your computer on your phone/3ds/whatnot. I admit, this was built for porn, hence why images are shown in the folder view, but I believe that this is an impressive enough project to put on my GitHub regardless.

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
	}
}
```

### Accounts:

```JSON
"admin":{
	"passHash":"e7cf3ef4f17c3999a94f2c6f612e8a888e5b1026878e4e19398b23bd38ec221a",
	"allow":["C:/Users/Admin/Documents"],
	"deny":["C:/Users/Admin/Documents/GitHub"],
	"canUpload":true
}
```
Breakdown:

- The `admin` key name is the username
- `passHash` is the SHA256 hash of the admin password (in this case, "Password")
- `allow` is an array of folders the user is allowed to view. If a folder starts with one of the strings in the array (including `""` for all folders), it is viewable. Leave empty if you want nothing to be viewable
- `deny` is an array that explicitly deines certain folders, usually subfolders of places in `allow`
- `canUpload` decides whether or not the user can use `/uploadForm` to upload files to the hosting computers

An empty userstring can be used for a "public" account. Because of how the server works, no login info defaults to both the username and password being empty strings. Useful if you need to share a file with someone on your wifi

### Redirs

Redirs (redirects) are a way of having short names to commonly used files/folders. I use `*home` to map to my custom-built NewTab. The syntax is simple

```JSON
"redirs":{
	"shortname":"/C:/Long/Path/Name"
}
```

Note the leading `/`. That's important