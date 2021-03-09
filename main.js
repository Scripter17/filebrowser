argparse=require("argparse");
express=require("express");
http=require("http");
https=require("https");
cookieParser=require("cookie-parser");
multer=require("multer");
path=require("path");
fs=require("fs");
crypto=require("crypto");
childProcess=require("child_process");

// == INITIALIZATION ==

// Argument parsing
parser=new argparse.ArgumentParser({
	description:"FileBrowser CLI",
	add_help:true
});
parser.add_argument("-config", "-c", {help:"Set config file", metavar:"config", default:"config.json"});
parser.add_argument("-hash", {help:"Calculate account password hash", metavar:"password"});
parser.add_argument("-no-warn", "-w", {help:"Disable warnings (probably a bad idea)", action:"store_true"});
kwargs=parser.parse_args();

// Get and validate config
getConfig();

// Handle -hash
if (kwargs.hash!=undefined){
	console.log(hash(kwargs.hash));
	process.exit();
}

// Set up server and middlewares
server=express();
server.use(express.urlencoded({extended: true}));
server.use(cookieParser());
server.use(express.static(path.resolve("resources")));
server.set("view engine", "pug");

// == URL handlers ==

// Upload handler
// TODO: Per-user file size limits
uploadHandler=multer({
	dest:"./files/",
	fileFilter:function(req, file, callback){
		// It works but the docs don't explain why
		callback(null, isAllowedPath("upload", getLoginFromReq(req)));
	},
	limits:{
		"fileSize":sizeStringToBytes(config.maxFileSize)
	}
}).single("file");

// Drive selection / Login screen
server.get("/", function(req, res){
	var login=getLoginFromReq(req);
	res.render("drives", {
			drives:getDriveData(login),
			username:login.username,
			canUpload:isAllowedPath("uploadForm", login),
			redirects:Object.keys(config.redirects).filter(redirect=>isAllowedPath(redirect, login)),
			title:"Drive selection",
			cache:true, filename:"drives"
		}
	);
});

// Login handler
server.post("/login", function(req, res){
	var login=req.body;
	if (!validateLogin(login)){
		// Don't want to set an invalid login
		login={username:"", password:""};
	}
	// Set login cookies for 1 week
	// TODO: Use GPG or something to make a login token that can't work after the week is up
	res.cookie("username", login.username || "", {maxAge:1000*60*60*24*7});
	res.cookie("password", login.password || "", {maxAge:1000*60*60*24*7});
	res.redirect(req.headers.referer);
});

// Upload form
server.get("/uploadForm", function(req, res){
	var login=getLoginFromReq(req);
	if (isAllowedPath("uploadForm", login)){
		res.render("uploadForm", {username:login.username, maxFileSize:config.maxFileSize, cache:true, filename:"uploadForm"});
	} else {
		sendError(req, res, {code:403, username:login.username});
	}
});

// Upload handler
server.post('/upload', function(req, res){
	var login=getLoginFromReq(req);
	if (isAllowedPath("upload", login)){
		uploadHandler(req, res, function (err){
			if (err instanceof multer.MulterError){ // TODO: Detect only file too large errors
				sendError(req, res, {code:413, username:login.username, desc:"File too large"});
			} else if (req.file==undefined){
				sendError(req, res, {code:400, username:login.username, desc:"No file given"});
			} else if (err){
				sendError(req, res, {code:500, username:login.username, desc:"Unknown error handling file upload"});
			} else {
				var uploadFolder=config.accounts[login.username].canUpload,
					uploadFolder=uploadFolder===true?config.defaultUploadLoc:uploadFolder, // true means upload to default folder
					filePath=path.join(uploadFolder, `${new Date().getTime()}-${login.username}-${req.file.originalname}`);
				moveFile(req.file.path, filePath); // fs.renameSync failes when moving between drives
				res.render("uploaded", {"file":req.file.originalname, username:login.username, cache:true, filename:"uploaded"});
			}
		});
	} else {
		sendError(req, res, {code:403, username:login.username});
	}
});

// Thumbnail generator
server.get("/thumb/*", function(req, res){
	var login=getLoginFromReq(req),
		loc=req.params[0], stream;
	if (!isAllowedPath(loc, login)){
		sendError(req, res, {code:403, username:login.username});
	} else if (pathIsFile(loc) && /\.a?png|jpe?g|jfif|gif|bmp$/.test(loc)){
		// Generate thumbnail and send it
		// A bit more involced than res.sendFIle, but oddly nostaligic for when this was built in the HTTP module
		var imageSize=/\d+x\d+/.exec(childProcess.spawnSync("magick", ["identify", loc]).stdout)[0].split("x").map(x=>parseInt(x));
		if (imageSize[0]*imageSize[1]>=10000*10000){
			res.sendFile(path.resolve("resources/TooBig.png"));
		} else {
			res.set("Content-Type", "image/jpeg");
			stream=childProcess.spawn("magick", [loc+"[0]", "-format", "jpeg", "-thumbnail", "512x512>", "-"], {"env":{"MAGICK_TEMPORARY_PATH":path.resolve("temp"), "MAGICK_DISK_LIMIT":sizeStringToBytes("4GiB")}});
			req.on("close", function(){stream.kill();});
			stream.stdout.on("data", function(data){res.write(Buffer.from(data));});
			stream.on("close", function(){res.end();});
		}
	} else if (pathIsFile(loc)){
		sendError(req, res, {code:400, username:login.username, desc:"File found but invalid for thumbnail generation"});
	} else if (pathIsDirectory(loc)){
		sendError(req, res, {code:400, username:login.username, desc:"Directories cannot be turned into thumbnails"});
	} else {
		sendError(req, res, {code:400, username:login.username, desc:"Tf did you do to trigger this?"});
	}
});

// LNK handler
// TODO: Make optional
server.get("/**.lnk", function(req, res){
	var login=getLoginFromReq(req),
		loc=req.params[0]+".lnk";
	if (isAllowedPath(lnk)){ // Also handles if the desitnation is allowed
		res.redirect("/"+getLnkLoc(loc));
	} else {
		sendError(req, res, {code:403, username:login.username});
	}
});

// Folder/file server
server.get("/*", function(req, res){
	var time=new Date().getTime(),
		login=getLoginFromReq(req),
		loc=req.params[0];
	if (!isAllowedPath(loc, login)){
		// Login invalid; Return 403
		sendError(req, res, {code:403, username:login.username});
	} else if (Object.keys(config.redirects).indexOf(loc)!=-1){
		// Handle redirects
		res.redirect(config.redirects[loc]);
	} else if (!pathExists(loc)){
		// File/dir not found
		sendError(req, res, {code:404, username:login.username});
	} else if (pathIsDirectory(loc)){
		// Send directory view
		if (!loc.endsWith("/")){
			res.redirect("/"+loc+"/");
		} else {
			res.render("folder", {
				contents:getFolderContents(loc, login),
				username:login.username,
				loc:loc,
				viewSettings:Object.assign(config.viewSettings, config.accounts[login.username].viewSettings || {}),
				cache:true, filename:"folder"
			});
		}
	} else {
		// Send file
		res.sendFile(loc, path.extname(loc)===""?{headers:{"Content-Type":"text"}}:{});
	}
});

// TODO: Built-in onionsite support?
if (config.useHTTPS){
	https.createServer({
		key: fs.readFileSync(config.httpsKey),
		cert:fs.readFileSync(config.httpsCert)
	}, server).listen(443);
} else {
	warn("Using HTTP because HTTPS is disabled in the selected config");
	http.createServer(server).listen(80);
}

// == FUNCTIONS ==
// Meta
function warn(text){
	if (!kwargs.noWarn){
		console.warn(text);
		return true;
	}
	return false;
}

// Generic filesystem
function pathIsDirectory(loc){
	try {
		return fs.lstatSync(loc).isDirectory();
	} catch {return false;}
}
function pathIsFile(loc){
	try {
		return !fs.lstatSync(loc).isDirectory();
	} catch {return false;}
}
function pathExists(loc){
	try {
		return fs.existsSync(loc);
	} catch {return false;}
}
function moveFile(oldLoc, newLoc){
	// Idea taken from https://stackoverflow.com/a/29105404/10720231
	try {
		fs.renameSync(oldLoc, newLoc);
	} catch {
		fs.copyFileSync(oldLoc, newLoc);
		fs.rmSync(oldLoc);
	}
}

// Drive/folder
function getDriveData(login){
	// TODO: Make this entire script support Linux
	return childProcess.execSync("wmic logicaldisk get name")
		.toString().replace(/ /g, "").split(/[\n\r]+/) // Extract non-empty lines
		.filter(x=>/[A-Za-z]:/.test(x)).map(x=>x+"/") // Filter out non-drive lines
		.filter(drive=>isAllowedPath(drive, login)); // Filter for drives the user can access
}
function getFolderContents(folderLoc, login){
	function abs(subFolder){
		return path.resolve(folderLoc, subFolder);
	}
	var contents=fs.readdirSync(folderLoc).map(subFolder=>"./"+subFolder)
		.filter(subFolder=>pathExists(abs(subFolder))) // "C:/System Volume Information" doesn't exist
		.filter(subFolder=>isAllowedPath(abs(subFolder), login)), // Don't let people see the stuff they can't access
		folders=contents.filter(subFolder=>pathIsDirectory(abs(subFolder))).map(x=>x+"/"),
		files=contents.filter(subFolder=>pathIsFile(abs(subFolder)));
	return {files:files, folders:folders};
}

// Config
function getConfig(){
	// Yeah yeah "global variables bad"
	// Look pretty much every major function in this mess of a program needs to reference the config and it doesn't change
	// It'd be stupider to *not* use a global variable here
	config=JSON.parse(fs.readFileSync(kwargs.config));
	validateConfig(config); // Yes this is supposed to throw an error on an invalid config
}
function validateConfig(){
	// Validate redirects
	var validViewSettings={
		"folder":{
			"imageMode": ["link", "embed", "thumbnail"],
			"videoMode": ["link", "embed"]
		}
	};
	for (let redirect in config.redirects){
		if (/^[a-z\d]*:\/[^\/]/i.test(config.redirects[redirect])){
			throw new Error(`Redirect "${redirect}" redirects to invalid path`);
		}
	}
	// Validate accounts
	for (let account in config.accounts){
		var accountData=config.accounts[account];
		if (accountData.passHash.length!=hash("", config).length){
			throw new Error(`${account} has an invalid password hash length`);
		}
		for (let denyElem of accountData.deny){
			if (!accountData.allow.some(allowElem=>denyElem.toLowerCase().startswith(allowElem.toLowerCase()))){
				warn(`${account} is denied ${denyElem} despite not being allowed any of its parents`);
			}
		}
		if (account==""){
			if (accountData.canUpload!=false){
				warn(`Default account has been granted upload permissions`);
			}
			if (hash("", config)!=accountData.passHash){
				warn(`Default account has a non-empty password`);
			}
		}
		if (account!="" && hash("", config)==accountData.passHash){
			warn(`${account} has an empty password`);
		}
		if (typeof accountData.canUpload=="string"){
			if (!pathExists(path.resolve(accountData.canUpload))){
				throw new Error(`${account}'s upload path has been set to a nonexistent location`);
			}
			if (!pathIsDirectory(accountData.canUpload)){ // pathIsDirectory is used for clarity
				throw new Error(`${account}'s upload path is not a directory`);
			}
		}
		for (let view in validViewSettings){
			for (let setting in validViewSettings[view]){
				if (!("viewSettings" in accountData) || !(view in accountData.viewSettings) || !(setting in accountData.viewSettings[view])){
					continue;
				}
				if (validViewSettings[view][setting].indexOf(accountData.viewSettings[view][setting])==-1){
					throw new Error(`${account}'s viewSettings.${view}.${setting} has an invalid value of "${accountData.viewSettings[view][setting]}"`);
				}
			}
		}
	}
	for (let view in validViewSettings){
		for (let setting in validViewSettings[view]){
			if (validViewSettings[view][setting].indexOf(config.viewSettings[view][setting])==-1){
				throw new Error(`viewSettings.${view}.${setting} has an invalid value of "${config.viewSettings[view][setting]}"`);
			}
		}
	}
	// Validate hashSalt
	if (config.hashSalt.length<8){
		// Should this be an error?
		warn(`hashSalt is short (less than 8 characters)`);
	}
	// Validate maxFileSize
	if (!isValidSizeString(config.maxFileSize)){
		throw new Error(`maxFileSize is set to an invalid value ("${config.maxFileSize}")`);
	}
	if (config.useHTTPS){
		if (!pathExists(config.httpsKey) || !pathIsFile(config.httpsKey)){
			throw new Error(`Nonexistent/non-file httpsCert provided ("${config.httpsKey}")`);
		}
		if (!pathExists(config.httpsKey) || !pathIsFile(config.httpsKey)){
			throw new Error(`Nonexistent/non-file httpsCert provided ("${config.httpsKey}")`);
		}
	}
}

// Login/Validation
function hash(text){
	// Hash used for passwords. Hash type and salt are set in config.json
	if (text===undefined){
		throw new Error("Provided hashstring is undefined (the type, not a string)");
	}
	return crypto.createHash(config.hashType).update(text+config.hashSalt).digest("hex");
}
function getLoginFromReq(req){
	// If the provided login is invalid, treat it as an empty login
	var rawReqLogin={username: req.cookies.username || "", password:req.cookies.password || ""};
	return validateLogin(rawReqLogin) ? rawReqLogin : {username:"", password:""};
}
function validateLogin(login){
	if (typeof login!="object" || !("username" in login) || !("password" in login)){
		return false;
	}
	if (!(login.username in config.accounts)){
		// Nonexistent username is automatically invalid
		warn(`Invalid login detected. Username: ${login.username}`);
		return false;
	}
	return config.accounts[login.username].passHash===hash(login.password);
}
function isAllowedPath(pathAbs, login){
	if (!(validateLogin(login)) || pathAbs===undefined){
		// Need to handle the case where the empty username isn't defined, since that's what getLoginFromReq defaults to
		// pathAbs is undefined if a .lnk file has no detected desitnation
		return false;
	}
	pathAbs=pathAbs.replace(/\\/g, "/"); // Windows using \\ as a folder delimiter is stupid
	if (pathAbs.toLowerCase()==="upload" || pathAbs.toLowerCase()==="uploadform"){
		// Arguably you can handle this in the allow key but that's dumb and jank
		return config.accounts[login.username].canUpload!=false;
	}
	if (pathAbs in config.redirects){
		return isAllowedPath(config.redirects[pathAbs].replace(/^\//, ""), login);
	}
	var isAllowed=config.accounts[login.username].allow.some(function(allowElem){
			// Allowing x:/y/z/ will automatically allow x:/y/, but not the rest of its contents
			return pathAbs.startsWith(allowElem) || allowElem.startsWith(pathAbs);
		}),
		isDenied=config.accounts[login.username].deny.some(denyElem=>pathAbs.startsWith(denyElem));
	// Allowing x:/y/ but disallowing x:/y/z/ works as expected
	// Gotta say, I like how I handled checking lnk files
	return isAllowed && !isDenied && (isLnkLoc(pathAbs)===isAllowedPath(getLnkLoc(pathAbs), login));
}

// Error handler
function sendError(req, res, args){
	// Got sick of doing this all over the place
	// Todo: Put the special errors (such as the 400's in the thumbnail code) in errorDescs
	var errorDescs={
		403:"File/Directory is not available for this login, assuming it exists",
		404:"File/Directory not found"
	};
	res.status(args.code);
	res.render("error", {
		code:args.code,
		text:args.desc || errorDescs[args.code] || "Error description not given",
		referer:req.headers.referer,
		username:args.username,
		cache:true, filename:"error"
	});
	// Todo: Maybe log IP?
	warn(`Error ${args.code} from ${args.username || "[empty username]"}: ${args.desc || errorDescs[args.code]}`);
}

// LNK handler
function getLnkLoc(lnkPath, skipValidation){
	// Todo: Replace this with a system I know can't break (Damn variable-length file formats)
	// Also todo: Replace LNKs entirely by using the @ system I used to use
	// (It was a single file in some dirs called `@` that had a list of other dirs/files to render in that dir)
	if (!skipValidation && !isLnkLoc(lnkPath)){
		return undefined
	}
	var lnkContents=fs.readFileSync(lnkPath).toString(),
		lnkRegex=/(?<=\0)[a-z]:\\[^\0]*?(?=\0)/i; // Apparently ?<= works in Node
	try {
		return lnkRegex.exec(lnkContents)[0].replace(/\\/g, "/");
	} catch {
		return undefined
	}
}
function isLnkLoc(lnkPath){
	// Honestly this is just here so sublime witll let me collapse the function
	return pathIsFile(lnkPath) && path.extname(lnkPath)=="lnk" && getLnkLoc(lnkPath, true);
}

// Sizestring for uploading
function sizeStringToBytes(sizeStr){
	if (sizeStr==-1){
		return Infinity;
	}
	var unitMap={
			"b":1,
			"kb":1000**1,"kib":1024**1,
			"mb":1000**2,"mib":1024**2,
			"gb":1000**2,"gib":1024**3
		},
		parseRegex=/^(\d+)(([KMG]i?)?[B])$/i,
		parsed=parseRegex.exec(sizeStr);
	return parseInt(parsed[1])*unitMap[parsed[2].toLowerCase()];
}
function isValidSizeString(sizeStr){
	try {
		sizeStringToBytes(sizeStr);
	} catch (e) {
		return false;
	}
	return true;
}
