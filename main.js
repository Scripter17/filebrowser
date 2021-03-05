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
parser=new argparse.ArgumentParser({
	description:"FileBrowser CLI",
	add_help:true
});
parser.add_argument("-config", "-c", {help:"Set config file", metavar:"config", default:"config.json"})
parser.add_argument("-hash", {help:"Calculate account password hash", metavar:"password"})
parser.add_argument("-no-warn", "-w", {help:"Disable warnings (probably a bad idea)", action:"store_true"})
kwargs=parser.parse_args();

config=getConfig();
server=express();
server.use(express.urlencoded({extended: true}));
server.use(cookieParser());
server.use(express.static(path.resolve("resources")));
server.set("view engine", "pug");

if (kwargs.hash!=undefined){
	console.log(hash(kwargs.password));
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
			canUpload:config.accounts[login.username].canUpload,
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
		res.render("uploadForm", {username:login.username, cache:true, filename:"uploadForm"})
	} else {
		sendError(res, {code:403});
	}
})

server.post('/upload', upload.single("file"), function(req, res){
	var login=getLoginFromReq(req);
	if (isAllowedPath("upload", login)){
		var filePath=path.join("./files/", new Date().getTime()+"-"+req.file.originalname);
		fs.renameSync(req.file.path, filePath);
		res.render("uploaded", {"file":path.basename(filePath), cache:true, filename:"uploaded"});
	} else {
		sendError(res, {code:403});
	}
});

server.get("/thumb/*", function(req, res){
	var login=getLoginFromReq(req),
		loc=req.params[0];
	if (!isAllowedPath(loc, login)){
		sendError(res, {code:403});
	} else if (isFile(loc) && /\.a?png|jpe?g|jfif|gif|bmp$/.test(loc)){
		// Generate thumbnail and send it
		// A bit more involced than res.sendFIle, but oddly nostaligic for when this was built in the HTTP module
		res.set("Content-Type", "image/jpeg")
		var stream=childProcess.spawn("convert", [loc, "-format", "jpeg", "-resize", "512x512>", "-"]);
		stream.stdout.on("data", function(data){
			res.write(Buffer.from(data));
		});
		stream.on("close", function(){
			res.end();
		})
	} else if (isFile(loc)){
		sendError(res, {code:400, desc:"File found but invalid for thumbnail generation"});
	} else if (isDirectory(loc)){
		sendError(res, {code:400, desc:"Directories cannot be turned into thumbnails"});
	} else {
		sendError(res, {code:400, desc:"Tf did you do to trigger this?"});
	}
});

// Folder/file server
server.get("/*", function(req, res){
	var time=new Date().getTime();
	var login=getLoginFromReq(req),
		loc=req.params[0];
	if (!isAllowedPath(loc, login)){
		// Login invalid; Return 403
		sendError(res, {code:403});
	} else if (Object.keys(config.redirs).indexOf(loc)!=-1){
		// Handle redirects
		res.redirect(config.redirs[loc]);
	} else if (!fs.existsSync(loc)){
		// File/dir not found
		sendError(res, {code:404});
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
	if (!kwargs.noWarn){
		console.warn("Using HTTP because HTTPS is disabled in the selected config");
	}
	http.createServer(server).listen(80);
}

function getDriveData(login){
	return childProcess.execSync("wmic logicaldisk get name")
		.toString().replace(/ /g, "").split(/[\n\r]+/)
		.filter(x=>/[A-Za-z]:/.test(x)).map(x=>x+"/")
		.filter(drive=>isAllowedPath(drive, login));
}

function getFolderContents(folderLoc, login){
	var absPath=path.resolve(folderLoc, subFolder),
		contents=fs.readdirSync(folderLoc).map(subFolder=>"./"+subFolder)
		.filter(subFolder=>fs.existsSync(absPath)) // "C:/System Volume Information" doesn't exist
		.filter(subFolder=>isAllowedPath(absPath, login)),
		folders=contents.filter(subFolder=>isDirectory(absPath)).map(x=>x+"/"),
		files=contents.filter(subFolder=>isFile(absPath));
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
function getConfig(){
	var config=JSON.parse(fs.readFileSync(kwargs.config));
	config.viewSettings.folder.imageMode||="link";
	config.viewSettings.folder.videoMode||="link";
	return config;
}
function hash(text){
	return crypto.createHash('sha256').update(text+config.hashSalt).digest("hex");
}

function getLoginFromReq(req){
	var rawReqLogin={username: req.cookies.username, password:req.cookies.password};
	return validateLogin(rawReqLogin) ? rawReqLogin : {username:"", password:""};
}
function validateLogin(login){
	if (Object.keys(config.accounts).indexOf(login.username)==-1){
		// Nonexistent username is automatically invalid
		return false;
	}
	return config.accounts[login.username].passHash==hash(login.password);
}

function isAllowedPath(pathAbs, login){
	pathAbs=pathAbs.replace(/\\/g, "/"); // Windows using \\ as a folder delimiter is stupid
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
	if (!kwargs.nowarn){
		console.warn(`Error ${args.code} (${args.desc || errorDescs[args.code]})`)
	}
}
