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
minimatch=require("minimatch");

// == INITIALIZATION ==

// Argument parsing
parser=new argparse.ArgumentParser({
	description:"Nasifier CLI",
	add_help:true
});
parser.add_argument("--config",    {help:"Set config file",                     metavar:"config", default:"config.json"});
parser.add_argument("--hash",      {help:"Calculate a passHash for the config", metavar:"password"});
parser.add_argument("--no-warn",   {help:"Disable warnings",                    action :"store_true"});
parser.add_argument("--hard-warn", {help:"Throw errors instead of warnings",    action :"store_true"});
parser.add_argument("--log-req",   {help:"Log every request  made by any user", action :"store_true"});
parser.add_argument("--log-res",   {help:"Log every response sent to any user", action :"store_true"});
kwargs=parser.parse_args();

// Get the config then move the cwd to the script's directory
// This used to resolve #1 but that job's been taken by elseViewHandler
kwargs.config=path.resolve(kwargs.config);
config=JSON.parse(fs.readFileSync(kwargs.config));
process.chdir(__dirname);
config=validateAndProcessConfig(config);

cachedImages=fs.readdirSync(config.cacheDir);

// Handle --hash
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
		loc=getLocFromReq(req),
		startTime=new Date().getTime(),
		viewSettings=getViewSettingsFromLogin(login);
	logReq(`Requested root (/)`, login, req);
	res.setHeader("Permissions-Policy", "interest-cohort=()");
	if (loc!=""){
		// If the basePath is set, there's no sense is returning driveView
		res.render("folder", {
			contents:getFolderContents(req, login),
			username:login.username, loc:rawLoc,
			viewSettings:getViewSettingsFromLogin(login),
			hideBack:true,
			cache:viewSettings.cacheViews, filename:"folder"
		});
		logRes(`Responded with folderView at basePath ${config.basePath}`, login, req, startTime);
	} else {
		res.render("drives", {
			drives:getDrives(login),
			username:login.username,
			canUpload:isAllowedPath("uploadForm", login),
			redirects:Object.keys(config.redirects).filter(redirect=>isAllowedPath(redirect, login)),
			title:"Drive selection",
			cache:viewSettings.cacheViews, filename:"drives"
		});
		logRes(`Responded with driveView`, login, req, startTime);
	}
});

// Login handler
server.post("/login", function(req, res){
	var login=req.body;
	logReq(`Attempting login`, login, req);
	res.setHeader("Permissions-Policy", "interest-cohort=()");
	if (!validateLogin(login)){
		logRes(`Invalid login`, login, req);
		warn(`Invalid login attempt: ${JSON.stringify({username:login.username, password:login.password})}`)
		login={username:"", password:""}; // Don't want to set an invalid login
	} else {
		logRes(`Valid login`, login, req);
	}
	// Set login cookies for 1 week
	// TODO: Use GPG or something to make a login token that can't work after the week is up
	res.cookie("username", login.username || "", {maxAge:1000*60*60*24*7});
	res.cookie("password", login.password || "", {maxAge:1000*60*60*24*7});
	res.redirect(req.headers.referer);
});

// Upload form
server.get("/uploadForm", function(req, res){
	var login=getLoginFromReq(req),
		startTime=new Date().getTime(),
		viewSettings=getViewSettingsFromLogin(login);
	logReq(`Loaded /uploadForm`, login, req);
	res.setHeader("Permissions-Policy", "interest-cohort=()");
	if (isAllowedPath("uploadForm", login)){
		res.render("uploadForm", {username:login.username, maxFileSize:config.maxFileSize, cache:viewSettings.cacheViews, filename:"uploadForm"});
		logRes(`Responded with uploadFormView`, login, req, startTime);
	} else {
		sendError(req, res, {code:403, username:login.username, loc:"uploadForm"});
		logRes(`Responded with 403`, login, req, startTime);
	}
});

// Upload handler
server.post('/upload', function(req, res){
	var login=getLoginFromReq(req),
		startTime=new Date().getTime(),
		viewSettings=getViewSettingsFromLogin(login);
	logReq(`Attempting to upload a file`, login, req);
	res.setHeader("Permissions-Policy", "interest-cohort=()");
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
				res.render("uploaded", {"file":req.file.originalname, username:login.username, cache:viewSettings.cacheViews, filename:"uploaded"});
				logRes(`Successfully uploaded file`, login, req, startTime);
			}
		});
	} else {
		sendError(req, res, {code:403, username:login.usernam, loc:"upload"});
		logRes(`Upload rejected with status 403`, login, req, startTime);
	}
});

// Folder/file server
server.get("/*", function(req, res){
	var startTime=new Date().getTime(),
		login=getLoginFromReq(req),
		rawLoc=req.params[0],
		loc=getLocFromReq(req),
		loguser=login.username||"default username",
		startTime=new Date().getTime(),
		viewSettings=getViewSettingsFromLogin(login);
	logReq(`Requested "${rawLoc}${"thumbnail" in req.query?"?thumbnail":""}"`, login, req);
	res.setHeader("Permissions-Policy", "interest-cohort=()");
	if (((config.basePath!="")==(rawLoc[1]==":") && !(rawLoc in config.redirects)) || !isAllowedPath(loc, login)){
		// Login invalid; Return 403
		// Jank ass if statement
		sendError(req, res, {code:403, username:login.username, loc:rawLoc});
		logRes(`Responded with 403 for "${rawLoc}"`, login, req, startTime);
	} else if (rawLoc in config.redirects){
		// Handle redirects
		res.redirect("/"+clipBasePath(config.redirects[loc]));
		logRes(`Redirected to "${clipBasePath(config.redirects[loc])}"`, login, req, startTime);
	} else if (!pathExists(loc)){
		// File/dir not found
		sendError(req, res, {code:404, username:login.username, loc:rawLoc});
		logRes(`Responded with 404 for "${rawLoc}"`, login, req, startTime);
	} else if (pathIsDirectory(loc)){
		// Send directory view
		res.render("folder", {
			contents:getFolderContents(req, login),
			username:login.username, loc:rawLoc,
			viewSettings:getViewSettingsFromLogin(login),
			hideBack:false,
			cache:viewSettings.cacheViews, filename:"folder"
		});
		logRes(`Responded with folderView for "${rawLoc}"`, login, req, startTime);
	} else {
		// Send file
		if ("thumbnail" in req.query && viewSettings.folder.imageRegex.test(loc)){
			var imageHash=hash(fs.readFileSync(loc))
			if (cachedImages.indexOf(imageHash)!=-1){
				logRes(`Sending pre-existing thumbnail for "${rawLoc}`, login, req);
				res.sendFile(path.resolve(path.join(config.cacheDir, imageHash)));
				logRes(`Sent pre-existing thumbnail for "${rawLoc}"`, login, req);
			} else {
				logRes(`Generating thumbnail for "${rawLoc}"`, login, req);
				var cacheFile=fs.createWriteStream(path.join(config.cacheDir, imageHash));
				res.set("Content-Type", "image/jpeg");
				let stream=child_process.spawn( // Note to self: var preserves address whereas let doesn't
					"magick", [loc+"[0]", "-format", "jpeg", "-scale", "512x512>", "-"],
					{"env":{"MAGICK_DISK_LIMIT": sizeStringToBytes("1GiB")}}
				);
				stream.stdout.on("data", function(data){
					res.write(Buffer.from(data));
					cacheFile.write(Buffer.from(data));
				});
				req.on("close", function(){
					if (stream.exitCode==null){stream.kill();}
				});
				stream.on("close", function(code){
					cacheFile.close();
					res.end();
					if (code==null){
						logRes(`Thumbnail gneration for "${rawLoc}" terminated early`, login, req, startTime);
					} else {
						logRes(`Generated thumbnail for "${rawLoc}"`, login, req, startTime);
						cachedImages.push(imageHash)
					}
				});
			}
		} else if (viewSettings.folder.handleLNKFiles && pathIsLNK(loc)){
			res.redirect("/"+clipBasePath(getLNKDestination(loc)));
			logRes(`Redirected to "${clipBasePath(getLNKDestination(loc))}" via LNK file`, login, req, startTime);
		} else {
			res.sendFile(loc, Object.assign({"dotfiles":"allow"}, path.extname(loc)==""?{headers:{"Content-Type":"text"}}:{}));
			logRes(`Sent file "${rawLoc}"`, login, req, startTime);
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
		throw new Error("Warning issued with --hard-warn enabled: "+text);
	}
	if (!kwargs.no_warn){
		console.warn(text);
	}
}
function logReq(text, login, req){
	if (kwargs.log_req){
		console.log(`${login.username||"default user"} at ${req.ip}: ${text}`);
	}
}
function logRes(text, login, req, startTime){
	if (kwargs.log_res){
		var timeText=startTime===undefined?"":` (time: ${Math.floor((new Date().getTime()-startTime)/100)/10}s)`;
		console.log(`${login.username||"default user"} at ${req.ip}: ${text}${timeText}`);
	}
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
	} catch {return false;}
	var resLoc=path.resolve(loc).replace(/\\/g, "/");
	if (fs.lstatSync(loc).isDirectory()!=loc.endsWith("/")){return false;}
	if (loc.indexOf("//")!=-1){return false;}
	if (fs.lstatSync(resLoc).isDirectory() && !resLoc.endsWith("/")){resLoc+="/";}
	return resolvePath(loc, true)===resLoc;
}
function moveFile(oldLoc, newLoc){
	// Idea taken from https://stackoverflow.com/a/29105404/10720231
	// Basically fs.renameSync("C:/File", "E:/File") doesn't work even if C: and E: are partitions on the same storage media
	try {
		fs.renameSync(oldLoc, newLoc);
	} catch {
		fs.copyFileSync(oldLoc, newLoc);
		fs.rmSync(oldLoc);
	}
}
function resolvePath(loc, fixCase, parentLoc){
	if (parentLoc===true){parentLoc=config.basePath;}
	retLoc=path.resolve(parentLoc||"", loc).replace(/\\/g, "/").replace(/^\//g, "");
	try {
		if (fixCase){
			retLoc=fs.realpathSync.native(retLoc).replace(/\\/g, "/");
		}
		if (fs.lstatSync(retLoc).isDirectory() && !retLoc.endsWith("/")){retLoc+="/";}
	} catch {warn(`resolvePath was given a non-existent loc ("${loc}", ${fixCase}, "${parentLoc}")`);}
	return retLoc;
}
function isParentDirOrSelf(loc, parentLoc){
	// Note: "Desktop.mkv".startsWith("Desktop") is true, unsurprisingly
	loc=loc.split("/").filter(x=>x!="");
	parentLoc=parentLoc.split("/").filter(x=>x!="");
	return parentLoc.every((x,i)=>loc[i]==parentLoc[i]);
}
function clipBasePath(loc, parentLoc){
	if (parentLoc===undefined){parentLoc=config.basePath;}
	if (!isParentDirOrSelf(loc, parentLoc)){return loc}
	return loc.split("/").splice(parentLoc.split("/").filter(x=>x!="").length).join("/");
}

// Drive/folder
function getDrives(login){
	return child_process.execSync("wmic logicaldisk get name")
		.toString().replace(/ /g, "").split(/[\n\r]+/) // Extract non-empty lines
		.filter(x=>/[A-Za-z]:/.test(x)).map(x=>x+"/") // Filter out non-drive lines
		.filter(drive=>isAllowedPath(drive, login)); // Filter for drives the user can access
}
function formatPathToLink(loc, parent, relative){
	// Lots of stringjank
	if (loc[0]=="/"){loc=loc.substr(1, loc.length-1);}
	loc=resolvePath(loc, false, parent);
	if (relative){
		loc=clipBasePath(loc, parent);
	}
	if (/^[a-z]:/i.test(loc)){
		loc=clipBasePath(loc);
		loc="/"+loc;
	} else {
		loc="./"+loc;
	}
	if (pathIsDirectory(loc) && !loc.endsWith("/")){loc+="/";}
	return loc;
}

function getFolderContents(req, login){
	var login=getLoginFromReq(req),
		loc=getLocFromReq(req),
		contents=fs.readdirSync(loc).map(content=>resolvePath(content, false, loc))
			//.concat(...(fs.readdirSync(loc).indexOf("@")!=-1?getAtContents(loc, login):[])) // Append atfile contents
			.filter(content=>pathExists(content)) // "C:/System Volume Information" doesn't exist, even though it does
			.filter(content=>isAllowedPath(content, login)) // Don't let people see the stuff they can't access
			.filter((content, i, arr)=>arr.indexOf(content)==i), // Don't want any duplicates
		folders=contents.filter(content=>pathIsDirectory(content)).map(content=>formatPathToLink(content, loc, true)),
		files=contents.filter(content=>pathIsFile(content)).map(content=>formatPathToLink(content, loc, true));
	return handleDDJ({files:files, folders:folders}, loc, login);
}
/*function getAtContents(loc, login, processed){
	// An atfile is a file just called @ in a folder
	// The lines of an atfile refer to other folder/files relative to it
	// Nasifier treats the files and the contents of the folders almost like LNK files
	var viewSettings=getViewSettingsFromLogin(login),
		ret=[];
	processed||=[];
	if (processed.indexOf(loc)!=-1){
		// Fixes a problem where an atfile that refers to itself gets caught in an infinite loop
		return ret;
	} else {
		processed.push(loc);
	}
	if (!viewSettings.folder.handleAtFiles || !pathIsFile(resolvePath("@", false, loc))){
		// If the user has atfiles disabled or there isn't one, just return an empty array
		return ret;
	}
	var lines=fs.readFileSync(resolvePath("@", false, loc)).toString().split(/[\r\n]+/)
			.map(x=>/^[ \t]*(.*?)[ \t]*$/.exec(x.split("//")[0])[1]) // Strips leading/tailing whitespaces as well as comments
			.filter(x=>x!="") // Have to do this afterwards because "  // xyz" needs to be filtered too
			.map(x=>resolvePath(x, false, loc)); // Handles relative paths
	for (var line of lines){
		line=resolvePath(line, false, loc);
		if (pathIsDirectory(line)){
			ret.push(...fs.readdirSync(line).map(x=>resolvePath(x, false, line)));
			ret.push(...getAtContents(line, login, processed));
		}
		ret.push(line);
	}
	return ret;
}*/
function handleDDJ(contents, loc, login){
	//if (contents.files.indexOf("..json")==-1){
	//	return contents;
	//}
	var sorts={
		"block": function(x, y){
			// Unsorted: ["a1","a10","a2","b2","b10a","b1"]
			// Sorted"   ["a1","a2","a10","b1","b2","b10a"]
			var xSplit=new Array(...x.matchAll(/[^\d]+|\d+/g)).map(z=>z[0]),
				ySplit=new Array(...y.matchAll(/[^\d]+|\d+/g)).map(z=>z[0]);
			for (var i=0; i<Math.min(xSplit.length, ySplit.length); i++){
				if (xSplit[i]!=ySplit[i]){
					if (/\d+/.test(xSplit[i]) && /\d+/.test(ySplit[i])){
						return parseInt(xSplit[i])-parseInt(ySplit[i]);
					} else {
						return (xSplit[i]>ySplit[i])-(xSplit[i]<ySplit[i]);
					}
				}
			}
			return (x>y)-(x<y);
		},
		"ascii":function(x, y){
			return (x>y)-(x<y);
		}
	};
	var filters={
		"inv":function(f){return function(x, y){return f(y, x)};},
		"nocase":function(f){return function(x, y){return f(x.toLowerCase(), y.toLowerCase())};}
	};
	function getSortFunction(sortString){
		var sortArray=(sortString||"block").split(":");
		/*if ((sortFunction[1]||"").toLowerCase()=="inv"){
			sortFunction=invSort(sorts[sortFunction[0]]);
		} else {
			sortFunction=sorts[sortFunction[0]];
		}*/
		sortFunction=sorts[sortArray[0]];
		for (var i=1; i<sortArray.length; i++){
			sortFunction=filters[sortArray[i]](sortFunction);
		}
		return sortFunction;
	}
	var viewSettings=getViewSettingsFromLogin(login);
	if (pathIsFile(path.join(loc, "..json"))){
		var DDJ=JSON.parse(fs.readFileSync(path.join(loc, "..json")).toString());
		var viewSettings=immutablyAssignNonObjectsRecursively(viewSettings, DDJ.viewSettings);
	}
	importContents=handleDDJImports(loc, login)
	contents.folders.push(...importContents.filter(x=>pathIsDirectory(x)));
	contents.files  .push(...importContents.filter(x=>pathIsFile(x)));
	// a.b?.c returns undefined if b is undefined instead of throwing an error
	// ?? is || but nullsy (""||0 === 0 && ""??0 === "")
	contents.folders=contents.folders.sort(getSortFunction(viewSettings.folder.folder?.sort??viewSettings.folder?.sort));
	contents.files  =contents.files  .sort(getSortFunction(viewSettings.folder.file  ?.sort??viewSettings.folder?.sort));
	return contents;
}
function handleDDJImports(loc, login, processed){
	var ret=[];
	processed||=[];
	if (processed.indexOf(loc)!=-1){
		return ret;
	} else {
		processed.push(loc);
	}
	if (!pathIsFile(resolvePath("..json", false, loc))){
		return ret;
	}
	var ddjImports=JSON.parse(fs.readFileSync(resolvePath("..json", false, loc)).toString()).imports||[];
	for (var ddjImport of ddjImports){
		ddjImport=resolvePath(ddjImport, false, loc);
		if (pathIsDirectory(ddjImport)){
			ret.push(...fs.readdirSync(ddjImport).map(x=>resolvePath(x, false, ddjImport)));
			ret.push(...getAtContents(ddjImport, login, processed));
		}
		ret.push(ddjImport);
	}
	return ret;
}

// Login/Validation
function hash(text, saltOverride, typeOverride){
	// Hash used for passwords. Hash type and salt are set in the config
	if (text===undefined){
		throw new Error("Provided hashstring is undefined (the type, not a string)");
	}
	if (saltOverride===undefined){saltOverride=config.hashSalt;} // salt||=config.hashSalt triggers on salt===""
	typeOverride||=config.hashType;
	return crypto.createHash(typeOverride).update(text+saltOverride).digest("hex");
}
function getLoginFromReq(req){
	// If the provided login is invalid, treat it as an empty login
	// Logging in normally sets the login cookies to empty, but this just makes sure in the case the user changes the cookies manually
	var rawReqLogin={username: req.cookies.username || "", password:req.cookies.password || ""};
	return validateLogin(rawReqLogin) ? rawReqLogin : {username:"", password:""};
}
function validateLogin(login){
	if (typeof login!="object" || !("username" in login) || !("password" in login)){
		warn("validateLogin recieved an invalid login argument");
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
		loc=resolvePath(loc, false, true);
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
			// Note to self: resolvePath("") gives a wrong answer (probably should fix that)
			if (isParentDirOrSelf(absLoc, allowElem) && allowElem.endsWith("/")!=pathIsDirectory(allowElem)){warn(`PathDir mismatch in isAllowedPath._isAllowed (${allowElem})`); return false;}
			return isParentDirOrSelf(absLoc, allowElem&&resolvePath(allowElem)) || isParentDirOrSelf(allowElem&&resolvePath(allowElem), absLoc);
		}) || (config.accounts[login.username].allowGlob??[]).some(function(allowGlobElem){
			return minimatch(absLoc, allowGlobElem, {dot:true}); // Why the fuck isn't dot=true the default
		});
	}
	function _isDenied(absLoc, login){
		return config.accounts[login.username].deny.some(function(denyElem){
			//denyElem=resolvePath(denyElem, false, true);
			if (isParentDirOrSelf(absLoc, denyElem) && denyElem.endsWith("/")!=pathIsDirectory(denyElem)){warn(`PathDir mismatch in isAllowedPath._isDenied (${denyElem})`); return true;}
			return isParentDirOrSelf(absLoc, resolvePath(denyElem));
		}) || (config.accounts[login.username].denyGlob??[]).some(function(denyGlobElem){
			return minimatch(absLoc, denyGlobElem, {dot:true});
		});
	}
	if (loc in config.redirects){return isAllowedPath(config.redirects[loc], login) && !_isDenied(loc, login);}
	if (!isParentDirOrSelf(loc, config.basePath) || !validateLogin(login) || loc===undefined){return false;}
	if (loc=="upload" || loc=="uploadForm"){return config.accounts[login.username].canUpload!=false;}
	var absLoc=resolvePath(loc);
	if (isParentDirOrSelf(absLoc, resolvePath(__dirname)) || absLoc==resolvePath(kwargs.config)){return false;}
	if (config.basePath=="" && loc[1]!=":"){return false;}
	return _isAllowed(absLoc, login) && !_isDenied(absLoc, login) && (config.handleLNKFiles && isLnkLoc(absLoc)?isAllowedPath(getLnkLoc(absLoc), login):true);
}

// Error handler
function sendError(req, res, args){
	// Got sick of doing this all over the place
	var viewSettings=getViewSettingsFromLogin({username:args.username});
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
		cache:viewSettings.cacheViews, filename:"error"
	});
	warn(`${args.username || "default user"} at ${req.ip}: Error ${args.code} "${args.desc || errorDescs[args.code]} (${args.loc || "unknown loc"})"`);
}

// LNK/redirect handling
function getLNKDestination(lnkPath, skipValidation){
	// Todo: Replace this with a system I know can't break (Damn variable-length file formats)
	if (!skipValidation && !pathIsLNK(lnkPath)){
		// Gotta love having to avoid stackoverflows
		warn(`getLNKDestination returned null ("${lnkPath}")`);
		return null;
	}
	var lnkContents=fs.readFileSync(lnkPath).toString(),
		lnkRegex=/(?<=\0)[a-z]:\\[^\0]*?(?=\0)/i; // Apparently ?<= works in Node
	try {
		var loc=lnkRegex.exec(lnkContents)[0].replace(/\\/g, "/");
		// if (!isParentDirOrSelf(loc, config.basePath)){return undefined;} // For some reason this causes problems with getLocFromReq
		return loc;
	} catch {
		warn(`getLNKDestination returned null ("${lnkPath}")`);
		return null;
	}
}
function pathIsLNK(lnkPath){
	// Honestly this comment is just here so sublime witll let me collapse the function
	return pathIsFile(lnkPath) && path.extname(lnkPath)==".lnk" && getLNKDestination(lnkPath, true);
}

// Sizestring for uploading
function sizeStringToBytes(sizeStr){
	if (sizeStr==-1){
		// JSON files don't support Infinity :/
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
		parseRegex=/^(\d+\.?\d*)((?:[KMGT]i?)?[B])$/i,
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

function validateAndProcessConfig(config){
	// Validate redirects
	var validViewSettings={
		"folder":{
			"imageMode": ["link", "embed", "thumbnail"],
			"videoMode": ["link", "embed"]
		}
	};
	function processViewSettings(viewSettings, account){
		try{
			if ("imageRegex" in viewSettings.folder){
				viewSettings.folder.imageRegex=new RegExp(viewSettings.folder.imageRegex);
			}
		} catch {throw new Error((account!==undefined?account+"'s ":"Default ")+"imageRegex is invalid");}
		try {
			if ("videoRegex" in viewSettings.folder){
				viewSettings.folder.videoRegex=new RegExp(viewSettings.folder.videoRegex);
			}
		} catch {throw new Error((account!==undefined?account+"'s ":"Default ")+"videoRegex is invalid");}
	}
	try {
		child_process.spawnSync("where magick");
		var magickInstalled=true;
	} catch {
		var magickInstalled=false;
	}

	// == PREPROCESSING ==
	// Account stuff
	for (let account in config.accounts){
		let accountData=config.accounts[account];
		for (let allowElem in accountData.allow){
			accountData.allow[allowElem]=resolvePath(accountData.allow[allowElem], false, config.basePath)
		}
		for (let denyElem in accountData.deny){
			accountData.deny[denyElem]=resolvePath(accountData.deny[denyElem], false, config.basePath)
		}
		if ("viewSettings" in accountData){processViewSettings(accountData.viewSettings, account);}
	}
	// HTTPS stuff
	if (config.httpPort===undefined){warn("Defaulting httpPort to 80"); config.httpPort=80;}
	if (config.httpsPort===undefined){warn("Defaulting httpsPort to 443"); config.httpsPort=443;}
	//config.httpsKey =resolvePath(config.httpsKey , false, path.dirname(kwargs.config));
	//config.httpsCert=resolvePath(config.httpsCert, false, path.dirname(kwargs.config));

	// Viewsettings stuff
	try{
		config.viewSettings.folder.imageRegex=new RegExp(config.viewSettings.folder.imageRegex);
	} catch {throw new Error("imageRegex is invalid");}
	try {
		config.viewSettings.folder.videoRegex=new RegExp(config.viewSettings.folder.videoRegex);
	} catch {throw new Error("videoRegex is invalid");}
	warn("Config validation isn't properly implemented yet because I keep changing stuff");
	return config;
}
function getViewSettingsFromLogin(login){
	// Annoyingly lone lines of code get sentenced to isolation
	if (!(login.username in config.accounts) || !("viewSettings" in config.accounts[login.username])){return config.viewSettings;}
	return immutablyAssignNonObjectsRecursively(config.viewSettings, config.accounts[login.username].viewSettings);
}
function immutablyAssignNonObjectsRecursively(baseObject, overwriteObject){
	var retObj={...baseObject}
	for (var i in overwriteObject){
		if (typeof retObj[i]=="object" && !(retObj[i] instanceof RegExp)){
			retObj[i]=immutablyAssignNonObjectsRecursively(retObj[i], overwriteObject[i]);
		} else {
			retObj[i]=overwriteObject[i];
		}
	}
	return retObj;
}
