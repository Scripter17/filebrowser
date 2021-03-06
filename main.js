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

// Initialize stuff
_defaultConfigPath=path.join(__dirname, "config.json")

parser=new argparse.ArgumentParser({
	description:"FileBrowser CLI",
	add_help:true
});
parser.add_argument("-config", "-c", {help:"Set config file", metavar:"config", default:"config.json"});
parser.add_argument("-hash", {help:"Calculate account password hash", metavar:"password"});
parser.add_argument("-no-warn", "-w", {help:"Disable warnings (probably a bad idea)", action:"store_true"});
kwargs=parser.parse_args();

config=getConfig();
server=express();
server.use(express.urlencoded({extended: true}));
server.use(cookieParser());
server.use(express.static(path.resolve("resources")));
server.set("view engine", "pug");

if (kwargs.hash!=undefined){
	// It took me like an hour to figure out why this gave the wrong hash (kwargs.password was undefined)
	console.log(hash(kwargs.hash));
	process.exit();
}

upload=multer({
	dest:"./files/",
	fileFilter:function(req, file, callback){
		// It works but the docs don't explain why
		callback(null, isAllowedPath("upload", getLoginFromReq(req)));
	}
});

// Drive selection / Login screen
server.get("/", function(req, res){
	var login=getLoginFromReq(req);
	res.render("drives", {
			drives:getDriveData(login),
			username:login.username,
			canUpload:isAllowedPath("uploadForm", login),
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
	res.cookie("username", login.username || "", {maxAge:1000*60*60*24*7});
	res.cookie("password", login.password || "", {maxAge:1000*60*60*24*7});
	res.redirect(req.headers.referer);
});

server.get("/uploadForm", function(req, res){
	var login=getLoginFromReq(req);
	if (isAllowedPath("uploadForm", login)){
		res.render("uploadForm", {username:login.username, cache:true, filename:"uploadForm"});
	} else {
		sendError(res, {code:403, username:login.username});
	}
});

server.post('/upload', upload.single("file"), function(req, res){
	var login=getLoginFromReq(req);
	if (isAllowedPath("upload", login)){
		var filePath=path.join("./files/", new Date().getTime()+"-"+req.file.originalname);
		fs.renameSync(req.file.path, filePath);
		res.render("uploaded", {"file":path.basename(filePath), cache:true, filename:"uploaded"});
	} else {
		sendError(res, {code:403, username:login.username});
	}
});

server.get("/thumb/*", function(req, res){
	var login=getLoginFromReq(req),
		loc=req.params[0];
	if (!isAllowedPath(loc, login)){
		sendError(res, {code:403, username:login.username});
	} else if (isFile(loc) && /\.a?png|jpe?g|jfif|gif|bmp$/.test(loc)){
		// Generate thumbnail and send it
		// A bit more involced than res.sendFIle, but oddly nostaligic for when this was built in the HTTP module
		res.set("Content-Type", "image/jpeg");
		var stream=childProcess.spawn("convert", [loc, "-format", "jpeg", "-resize", "512x512>", "-"]);
		stream.stdout.on("data", function(data){
			res.write(Buffer.from(data));
		});
		stream.on("close", function(){
			res.end();
		});
	} else if (isFile(loc)){
		sendError(res, {code:400, desc:"File found but invalid for thumbnail generation", username:login.username});
	} else if (isDirectory(loc)){
		sendError(res, {code:400, desc:"Directories cannot be turned into thumbnails", username:login.username});
	} else {
		sendError(res, {code:400, desc:"Tf did you do to trigger this?", username:login.username});
	}
});

server.get("/**.lnk", function(req, res){
	var login=getLoginFromReq(req),
		loc=req.params[0]+".lnk";
	if (isAllowedPath(loc, login) && isAllowedPath(getLnkLoc(loc), login)){
		res.redirect("/"+getLnkLoc(loc));
	} else {
		sendError(res, {code:403, username:login.username});
	}
});

// Folder/file server
server.get("/*", function(req, res){
	var time=new Date().getTime(),
		login=getLoginFromReq(req),
		loc=req.params[0];
	if (!isAllowedPath(loc, login)){
		// Login invalid; Return 403
		sendError(res, {code:403, username:login.username});
	} else if (Object.keys(config.redirs).indexOf(loc)!=-1){
		// Handle redirects
		res.redirect(config.redirs[loc]);
	} else if (!fs.existsSync(loc)){
		// File/dir not found
		sendError(res, {code:404, username:login.username});
	} else if (isDirectory(loc)){
		// Send directory view
		if (!loc.endsWith("/")){
			res.redirect("/"+loc+"/");
		} else {
			var folderContents=getFolderContents(loc, login);
			res.render("folder", {
				files:folderContents.files,
				folders:folderContents.folders,
				username:login.username,
				loc:loc,
				viewSettings:config.viewSettings.folder,
				cache:true, filename:"folder"
			});
		}
	} else {
		// Send file
		res.sendFile(loc, path.extname(loc)==""?{headers:{"Content-Type":"text"}}:{});
	}
});

if (config.useHTTPS){
	https.createServer({
		key: fs.readFileSync(config.httpsKey),
		cert:fs.readFileSync(config.httpsCert)
	}, server).listen(443);
} else {
	warn("Using HTTP because HTTPS is disabled in the selected config");
	http.createServer(server).listen(80);
}

// Drive/folder stuff
function getDriveData(login){
	return childProcess.execSync("wmic logicaldisk get name")
		.toString().replace(/ /g, "").split(/[\n\r]+/)
		.filter(x=>/[A-Za-z]:/.test(x)).map(x=>x+"/")
		.filter(drive=>isAllowedPath(drive, login));
}

function getFolderContents(folderLoc, login){
	function abs(subFolder){
		return path.resolve(folderLoc, subFolder);
	}
	var contents=fs.readdirSync(folderLoc).map(subFolder=>"./"+subFolder)
		.filter(subFolder=>fs.existsSync(abs(subFolder))) // "C:/System Volume Information" doesn't exist
		.filter(subFolder=>isAllowedPath(abs(subFolder), login)),
		folders=contents.filter(subFolder=>isDirectory(abs(subFolder))).map(x=>x+"/"),
		files=contents.filter(subFolder=>isFile(abs(subFolder)));
	return {files:files, folders:folders};
}

function isDirectory(loc){
	try {
		return fs.lstatSync(loc).isDirectory();
	} catch {
		return false;
	}
}

function isFile(loc){
	return !isDirectory(loc);
}

// Gross internals to ensure security
function warn(text){
	if (!kwargs.noWarn){
		console.warn(text);
		return true;
	}
	return false;
}

function getConfig(){
	try {
		var config=JSON.parse(fs.readFileSync(kwargs.config));
	} catch (e){
		warn("Selected config file failed to open/parse; Opening default config");
		var config=JSON.parse(fs.readFileSync(_defaultConfigPath));
	}
	config.viewSettings.folder.imageMode||="link";
	config.viewSettings.folder.videoMode||="link";
	return config;
}

function hash(text){
	if (text===undefined){
		warn("Hash text is undefined");
	}
	return crypto.createHash('sha256').update(text+config.hashSalt).digest("hex");
}

function getLoginFromReq(req){
	var rawReqLogin={username: req.cookies.username, password:req.cookies.password};
	return validateLogin(rawReqLogin) ? rawReqLogin : {username:"", password:""};
}

function validateLogin(login){
	if (Object.keys(config.accounts).indexOf(login.username)==-1){
		// Nonexistent username is automatically invalid
		warn(`Invalid login detected. Username: ${login.username}`);
		return false;
	}
	return config.accounts[login.username].passHash==hash(login.password);
}

function isAllowedPath(pathAbs, login){
	pathAbs=pathAbs.replace(/\\/g, "/"); // Windows using \\ as a folder delimiter is stupid
	if (!(login.username in config.accounts)){
		warn("Login not found in isAllowedPath (?)");
		return false;
	}
	if (pathAbs.toLowerCase()=="upload" || pathAbs.toLowerCase()=="uploadform"){
		return config.accounts[login.username].canUpload;
	}
	var isAllowed=config.accounts[login.username].allow.some(function(allowElem){
			// Allowing x:/y/z/ will automatically allow x:/y/, but not the rest of its contents
			return pathAbs.startsWith(allowElem) || allowElem.startsWith(pathAbs);
		}),
		isDenied=config.accounts[login.username].deny.some(denyElem=>pathAbs.startsWith(denyElem));
	// Allowing x:/y/ but disallowing x:/y/z/ works as expected
	return isAllowed && !isDenied;
}

function sendError(res, args){
	var errorDescs={
		403:"File/Directory is not available for this login, assuming it exists",
		404:"File/Directory not found"
	};
	res.status(args.code);
	res.render("error", {
		code:args.code,
		text:args.desc || errorDescs[args.code],
		cache:true, filename:"error"
	});
	warn(`Error ${args.code} from ${args.username || "[empty username]"}: ${args.desc || errorDescs[args.code]}`);
}

function getLnkLoc(lnkPath){
	// TODO: Replace this with a system I know can't break
	var lnkContents=fs.readFileSync(lnkPath).toString(),
		lnkRegex=/(?<=\0)[a-z]:\\[^\0]*?(?=\0)/i;
	return lnkRegex.exec(lnkContents)[0].replace(/\\/g, "/");
}
