argparse=require("argparse");
express=require("express");
http=require("http");
https=require("https");
cookieParser=require("cookie-parser");
multer=require("multer");
path=require("path");
fs=require("fs");
crypto=require("crypto");
child_process=require("child_process");
true_case_path=require("true-case-path");

// == INITIALIZATION ==

// Argument parsing
parser=new argparse.ArgumentParser({
	description:"FileBrowser CLI",
	add_help:true
});
parser.add_argument("-config", {help:"Set config file", metavar:"config", default:"config.json"});
parser.add_argument("-hash", {help:"Calculate account password hash", metavar:"password"});
parser.add_argument("-no-warn", {help:"Disable warnings (probably a bad idea)", action:"store_true"});
parser.add_argument("-hard-warn", {help:"Throw errors instead of warnings (also probably a bad idea)", action:"store_true"});
parser.add_argument("-log-req", {help:"Log every request made by any user", action:"store_true"});
parser.add_argument("-log-res", {help:"Log every request made by any user", action:"store_true"});
kwargs=parser.parse_args();
console.log(kwargs)
// Get and validate config
//absPathCache={};
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
	dest:config.defaultUploadLoc,
	fileFilter:function(req, file, callback){
		// It works but the docs don't explain why
		callback(null, isAllowedPath("upload", getLoginFromReq(req)));
	},
	limits:{"fileSize":sizeStringToBytes(config.maxFileSize)}
}).single("file");

// Drive selection / Login screen
server.get("/", function(req, res){
	var login=getLoginFromReq(req),
		rawLoc=req.params[0],
		loc=getLocFromReq(req);
	if (loc!=""){
		res.render("folder", {
			contents:getFolderContents(req),
			username:login.username, loc:rawLoc,
			viewSettings:getViewSettingsFromLogin(login),
			hideBack:true,
			cache:config.viewSettings.cacheViews, filename:"folder"
		});
	} else {
		res.render("drives", {
			drives:getDriveData(login),
			username:login.username,
			canUpload:isAllowedPath("uploadForm", login),
			redirects:Object.keys(config.redirects).filter(redirect=>isAllowedPath(redirect, login)),
			title:"Drive selection",
			cache:config.viewSettings.cacheViews, filename:"drives"
		});
	}
});

// Login handler
server.post("/login", function(req, res){
	var login=req.body;
	if (!validateLogin(login)){
		// Don't want to set an invalid login
		warn(`Invalid login attempt: ${JSON.stringify({username:login.username, password:login.password})}`)
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
		res.render("uploadForm", {username:login.username, maxFileSize:config.maxFileSize, cache:config.viewSettings.cacheViews, filename:"uploadForm"});
	} else {
		sendError(req, res, {code:403, username:login.username, loc:"uploadForm"});
	}
});

// Upload handler
server.post('/upload', function(req, res){
	var login=getLoginFromReq(req);
	if (isAllowedPath("upload", login)){
		uploadHandler(req, res, function (err){
			if (err instanceof multer.MulterError){ // TODO: Detect only file too large errors
				sendError(req, res, {code:413, username:login.username, desc:"File too large", loc:"upload"});
			} else if (req.file==undefined){
				sendError(req, res, {code:400, username:login.username, desc:"No file given", loc:"upload"});
			} else if (err){
				sendError(req, res, {code:500, username:login.username, desc:"Unknown error handling file upload", loc:"upload"});
			} else {
				var uploadFolder=config.accounts[login.username].canUpload,
					uploadFolder=uploadFolder===true?config.defaultUploadLoc:uploadFolder, // true means upload to default folder
					filePath=path.join(uploadFolder, `${new Date().getTime()}-${login.username}-${req.file.originalname}`);
				moveFile(req.file.path, filePath); // fs.renameSync failes when moving between drives
				res.render("uploaded", {"file":req.file.originalname, username:login.username, cache:config.viewSettings.cacheViews, filename:"uploaded"});
			}
		});
	} else {
		sendError(req, res, {code:403, username:login.usernam, loc:"upload"});
	}
});

// LNK handler
// TODO: Make optional
server.get("/**.lnk", function(req, res){
	var login=getLoginFromReq(req),
		loc=getLocFromReq(req, ".lnk");
	if (!isAllowedPath(loc, login)){ // Also handles if the desitnation is allowed
		sendError(req, res, {code:403, username:login.username, loc:loc});
	} else if (loc in config.redirects){
		res.redirect("/"+clipBasePath(config.redirects[loc]));
	} else {
		res.redirect("/"+clipBasePath(getLnkLoc(loc)));
	}
});

// Folder/file server
server.get("/*", function(req, res){
	var time=new Date().getTime(),
		login=getLoginFromReq(req),
		rawLoc=req.params[0],
		loc=getLocFromReq(req),
		loguser=login.username||"default username";
	if ((config.basePath!="" && rawLoc[1]==":") || !isAllowedPath(loc, login)){
		// Login invalid; Return 403
		sendError(req, res, {code:403, username:login.username, loc:rawLoc});
	} else if (rawLoc in config.redirects){
		// Handle redirects
		res.redirect("/"+clipBasePath(config.redirects[loc]));
	} else if (!pathExists(loc)){
		// File/dir not found
		sendError(req, res, {code:404, username:login.username, loc:rawLoc});
	} else if (pathIsDirectory(loc)){
		// Send directory view
		if (!loc.endsWith("/")){
			res.redirect("/"+loc+"/");
		} else {
			res.render("folder", {
				contents:getFolderContents(req),
				username:login.username, loc:rawLoc,
				viewSettings:getViewSettingsFromLogin(login),
				hideBack:false,
				cache:config.viewSettings.cacheViews, filename:"folder"
			});
		}
	} else {
		// Send file
		if ("thumbnail" in req.query && config.viewSettings.folder.imageRegex.test(loc)){
			//var imageSize=/\d+x\d+/.exec(child_process.spawnSync("magick", ["identify", loc]).stdout)[0].split("x").map(x=>parseInt(x));
			//if (imageSize[0]*imageSize[1]>=10000*10000){
			//	res.sendFile(path.resolve("resources/TooBig.png"));
			//} else {
			res.set("Content-Type", "image/jpeg");
			let stream=child_process.spawn( // For some reason using let instead of var makes stream.kill work right
					"magick", [loc+"[0]", "-format", "jpeg", "-scale", "512x512>", "-"],
					{"env":{"MAGICK_DISK_LIMIT":sizeStringToBytes("1GiB")}}
				);
			stream.stdout.on("data", function(data){res.write(Buffer.from(data));});
			req.on("close", function(){stream.kill();});
			stream.on("close", function(){res.end();});
			//}
		} else {
			res.sendFile(loc, path.extname(loc)===""?{headers:{"Content-Type":"text"}}:{});
		}
	}
});

// TODO: Built-in onionsite support?
if (config.useHTTPS){
	https.createServer({
		key: fs.readFileSync(config.httpsKey),
		cert:fs.readFileSync(config.httpsCert)
	}, server).listen(config.httpsPort);
} else {
	warn("Using HTTP because HTTPS is disabled in the selected config");
	http.createServer(server).listen(config.httpPort);
}

// == FUNCTIONS ==
// Meta
function warn(text){
	if (kwargs.hard_warn){
		throw new Error("Warning issued with -hard-warn enabled");
	}
	if (!kwargs.no_warn){
		console.warn(text);
		return true;
	}
	return false;
}

// Generic filesystem
function pathIsDirectory(loc){
	//try {
		return pathExists(loc) && fs.lstatSync(loc).isDirectory();
	//} catch {return false;}
}
function pathIsFile(loc){
	//try {
		return pathExists(loc) && !fs.lstatSync(loc).isDirectory();
	//} catch {return false;}
}
function pathExists(loc){
	try {
		fs.lstatSync(loc);
		var resLoc=path.resolve(loc).replace(/\\/g, "/");
		if (fs.lstatSync(resLoc).isDirectory() && !resLoc.endsWith("/")){resLoc+="/";}
		return resolvePath(loc, true)===resLoc;
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
function resolvePath(loc, fixCase, absolute){
	if (typeof loc!="object"){loc=[loc];}
	try{
		loc=path.resolve(absolute?config.basePath:"", ...loc).replace(/\\/g, "/").replace(/^\//g, "");
		if (fixCase){
			// Did a test, 100,000 calls of this takes about 10s
			loc=true_case_path.trueCasePathSync(loc).replace(/\\/g, "/");
		}
		if (fs.lstatSync(loc).isDirectory() && !loc.endsWith("/")){loc+="/";}
		return loc;
	} catch {return null;}
}
function isParentDirOrSelf(loc, parentLoc){
	// Note: "Desktop.mkv".startsWith("Desktop") is true, unsurprisingly
	var ln=loc===null, pln=parentLoc===null;
	if (loc===null){warn(`Null passed into isParentDirOrSelf (${ln?"loc":""}${ln&&pln?" & ":""}${pln?"parentLoc":""})`);}
	if (ln || pln){return false;}
	if (loc===undefined){throw new Error("a")}
	loc=loc.split("/").filter(x=>x!="");
	parentLoc=parentLoc.split("/").filter(x=>x!="");
	return parentLoc.every((x,i)=>loc[i]==parentLoc[i]);
}
function clipBasePath(loc){
	if (!isParentDirOrSelf(loc, config.basePath)){throw new Error("aaa")}
	return loc.split("/").splice(config.basePath.split("/").filter(x=>x!="").length).join("/");
}

// Drive/folder
function getDriveData(login){
	// TODO: Make this entire script support Linux
	return child_process.execSync("wmic logicaldisk get name")
		.toString().replace(/ /g, "").split(/[\n\r]+/) // Extract non-empty lines
		.filter(x=>/[A-Za-z]:/.test(x)).map(x=>x+"/") // Filter out non-drive lines
		.filter(drive=>isAllowedPath(drive, login)); // Filter for drives the user can access
}
function getFolderContents(req){
	var login=getLoginFromReq(req),
		folderLoc=getLocFromReq(req);
	var contents=fs.readdirSync(folderLoc).map(subFolder=>"./"+subFolder)
		.filter(subFolder=>pathExists(resolvePath([folderLoc, subFolder]))) // "C:/System Volume Information" doesn't exist
		.filter(subFolder=>isAllowedPath(resolvePath([folderLoc, subFolder]), login)), // Don't let people see the stuff they can't access
		folders=contents.filter(subFolder=>pathIsDirectory(resolvePath([folderLoc, subFolder]))).map(x=>x+"/"),
		files=contents.filter(subFolder=>pathIsFile(resolvePath([folderLoc, subFolder])));
	return {files:files, folders:folders};
}

// Login/Validation
function hash(text, salt, type){
	// Hash used for passwords. Hash type and salt are set in config.json
	if (text===undefined){
		throw new Error("Provided hashstring is undefined (the type, not a string)");
	}
	if (salt===undefined){salt=config.hashSalt;} // salt||=config.hashSalt triggers on salt=""
	type||=config.hashType;
	return crypto.createHash(type).update(text+salt).digest("hex");
}
function getLoginFromReq(req){
	// If the provided login is invalid, treat it as an empty login
	var rawReqLogin={username: req.cookies.username || "", password:req.cookies.password || ""};
	return validateLogin(rawReqLogin) ? rawReqLogin : {username:"", password:""};
}
function validateLogin(login){
	if (typeof login!="object" || !("username" in login) || !("password" in login)){
		warn("Invalid login passed into validateLogin")
		return false;
	}
	if (!(login.username in config.accounts)){
		// Nonexistent username is automatically invalid
		warn(`Invalid login detected. Username: ${login.username}`);
		return false;
	}
	return config.accounts[login.username].passHash===hash(login.password);
}
function getLocFromReq(req, suffix){
	var loc=(req.params[0]||"")+(suffix||"");
	if (config.basePath=="" || loc in config.redirects){
		return loc;
	} else {
		loc=resolvePath([config.basePath, loc]);
		if (loc===undefined || !isParentDirOrSelf(loc, config.basePath)){loc="";}
		return loc;
	}
}
function isAllowedPath(loc, login){
	// This is easily the single most important (and most jank) function in this program
	// Note to self: curl --insecure --path-as-is https://localhost/C:/AllowedPath/../../C:/NotAllowedPath
	function _isAllowed(absLoc, login){
		return config.accounts[login.username].allow.some(function(allowElem){
			// Allowing x:/y/z/ will automatically allow x:/y/, but not the rest of its contents
			if (allowElem.endsWith("/")!=pathIsDirectory(allowElem)){warn("PathDir mismatch in isAllowedPath"); return false;}
			return isParentDirOrSelf(absLoc, allowElem&&resolvePath(allowElem)) || isParentDirOrSelf(allowElem&&resolvePath(allowElem), absLoc);
		});
	}
	function _isDenied(absLoc, login){
		return config.accounts[login.username].deny.some(denyElem=>isParentDirOrSelf(absLoc, resolvePath(denyElem)));
	}
	if (loc in config.redirects){return isAllowedPath(config.redirects[loc], login) && !_isDenied(loc, login);}
	if (!isParentDirOrSelf(loc, config.basePath) || !validateLogin(login) || loc===undefined){return false;}
	if (loc=="upload" || loc=="uploadForm"){return config.accounts[login.username].canUpload!=false;}
	absLoc=resolvePath(loc);
	if (isParentDirOrSelf(absLoc, resolvePath(__dirname)) || absLoc==resolvePath(kwargs.config)){return false;}
	return _isAllowed(absLoc, login) && !_isDenied(absLoc, login) && (isLnkLoc(absLoc)?isAllowedPath(getLnkLoc(absLoc), login):true);
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
		desc:args.desc || errorDescs[args.code] || "Error description not given",
		back:req.headers.referer || "/",
		username:args.username,
		cache:config.viewSettings.cacheViews, filename:"error"
	});
	// Todo: Maybe log IP?
	warn(`Error ${args.code} from ${args.username || "default user"}: ${args.desc || errorDescs[args.code]} (${args.loc || "unknown loc"})`);
}

// LNK/redirect handling
function getLnkLoc(lnkPath, skipValidation){
	// Todo: Replace this with a system I know can't break (Damn variable-length file formats)
	// Also todo: Replace LNKs entirely by using the @ system I used to use
	// (It was a single file in some dirs called `@` that had a list of other dirs/files to render in that dir)
	if (!skipValidation && !isLnkLoc(lnkPath)){
		return null
	}
	var lnkContents=fs.readFileSync(lnkPath).toString(),
		lnkRegex=/(?<=\0)[a-z]:\\[^\0]*?(?=\0)/i; // Apparently ?<= works in Node
	try {
		var loc=lnkRegex.exec(lnkContents)[0].replace(/\\/g, "/");
		// if (!isParentDirOrSelf(loc, config.basePath)){return undefined;} // For some reason this causes problems with getLocFromReq
		return loc;
	} catch {
		return null
	}
}
function isLnkLoc(lnkPath){
	// Honestly this comment is just here so sublime witll let me collapse the function
	return pathIsFile(lnkPath) && path.extname(lnkPath)==".lnk" && getLnkLoc(lnkPath, true);
}

// Sizestring for uploading
function sizeStringToBytes(sizeStr){
	if (sizeStr==-1){
		return Infinity;
	}
	if (typeof sizeStr=="number"){
		return sizeStr;
	}
	var unitMap={
			"b":1,
			"kb":1000**1,"kib":1024**1,
			"mb":1000**2,"mib":1024**2,
			"gb":1000**3,"gib":1024**3,
			"tb":1000**4,"tib":1024**4 // Because I can
		},
		parseRegex=/^(\d+)(([KMGT]i?)?[B])$/i,
		parsed=parseRegex.exec(sizeStr);
	return parseFloat(parsed[1])*unitMap[parsed[2].toLowerCase()];
}
function isValidSizeString(sizeStr){
	try {
		sizeStringToBytes(sizeStr);
		return true;
	} catch (e) {
		return false;
	}
}

// Config
function getConfig(){
	// Yeah I know global variables are bad. Shut up
	config=validateConfig(JSON.parse(fs.readFileSync(kwargs.config)));
}
function validateConfig(config){
	// Validate redirects
	var validViewSettings={
		"folder":{
			"imageMode": ["link", "embed", "thumbnail"],
			"videoMode": ["link", "embed"]
		}
	};
	try {
		child_process.spawnSync("where magick");
		var magickInstalled=true;
	} catch {
		var magickInstalled=false;
	}
	for (let redirect in config.redirects){
		//if (/^[a-z\d]*:\/[^\/]/i.test(config.redirects[redirect])){
		//	throw new Error(`Redirect "${redirect}" redirects to invalid path`);
		//}
	}
	// Validate accounts
	for (let account in config.accounts){
		var accountData=config.accounts[account];
		if (accountData.passHash.length!=hash("", config.hashSalt, config.hashType).length){
			throw new Error(`${account} has an invalid passHash length`);
		}
		for (let denyElem of accountData.deny){
			if (!accountData.allow.some(allowElem=>isParentDirOrSelf(denyElem, allowElem))){
				warn(`${account} is denied ${denyElem} despite not being allowed any of its parents`);
			}
		}
		if (account==""){
			if (accountData.canUpload!=false){
				warn(`Default account has been granted upload permissions`);
			}
			if (hash("", config.hashSalt, config.hashType)!=accountData.passHash){
				warn(`Default account has a non-empty password`);
			}
		}
		if (account!="" && hash("", config.hashSalt, config.hashType)==accountData.passHash){
			warn(`${account} has an empty password`);
		}
		if (typeof accountData.canUpload=="string"){
			if (!pathExists(accountData.canUpload)){
				throw new Error(`${account}'s upload path has been set to a nonexistent location`);
			}
			if (!pathIsDirectory(accountData.canUpload)){
				throw new Error(`${account}'s upload path is not a directory`);
			}
		}
		for (let view in validViewSettings){
			for (let setting in validViewSettings[view]){
				if (!("viewSettings" in accountData) || !(view in accountData.viewSettings) || !(setting in accountData.viewSettings[view])){
					continue;
				}
				if (view=="folder" && setting=="imageMode" && accountData.viewSettings[view][setting]=="thumbnail" && !magickInstalled){
					throw new Error(`${account}'s viewSettings.folder.imageMode is set to thumbnail depite imageMagick not being installed`)
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
			if (view=="folder" && setting=="imageMode" && config.viewSettings[view][setting]=="thumbnail" && !magickInstalled){
				throw new Error(`viewSettings.${view}.${setting} is set to thumbnail despite imageMagick not being installed`);
			}
		}
	}
	if (!pathExists(config.defaultUploadLoc)){
		throw new Error(`Default upload path has been set to a nonexistent location`);
	}
	if (!pathIsDirectory(config.defaultUploadLoc)){
		throw new Error(`Default upload path is not a directory`);
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
			throw new Error(`Nonexistent/non-file httpsKey provided ("${config.httpsKey}")`);
		}
		if (!pathExists(config.httpsCert) || !pathIsFile(config.httpsCert)){
			throw new Error(`Nonexistent/non-file httpsCert provided ("${config.httpsCert}")`);
		}
	}
	// == PARSING ==
	config.viewSettings.folder.imageRegex=new RegExp(config.viewSettings.folder.imageRegex);
	config.viewSettings.folder.videoRegex=new RegExp(config.viewSettings.folder.videoRegex);
	return config;
}
function getViewSettingsFromLogin(login){
	// Annoyingly lone lines of code get sentenced to isolation
	return Object.assign(config.viewSettings, (config.accounts[login.username] || {viewsettings:undefined}).viewSettings || {});
}
