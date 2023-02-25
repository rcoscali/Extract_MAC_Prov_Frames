var os = require('os');
var express = require('express');
var router = express.Router();
var mime = require('mime');
var reader = require ("buffered-reader");
var formidable = require('formidable');
var path = require('path');
var fs = require('fs');
const bodyParser = require("body-parser");
const sqlite3 = require('sqlite3').verbose();
const {exec} = require("child_process");
const form = formidable({uploadDir: os.tmpdir()});
var app = require('../app');

const DbLogPath = process.env.HOME + '/Public/MAC_Prov_Extract/var/log';
const DbDirPath = process.env.HOME + '/Public/MAC_Prov_Extract/var/lib';
const DbFilePath = DbDirPath + '/keystore.db';

// Instanciate keystore DB
var keystoredb =
    new sqlite3.Database(
        DbFilePath,
        sqlite3.OPEN_READWRITE | sqlite3.OPEN_FULLMUTEX | sqlite3.OPEN_PRIVATECACHE,
        (err) =>
        {
            if (err)
            {
                console.error(err.message);
                process.exit(1);
            }
            else
	    {
                console.log('****** Keys DB openned !');

                var app = express();

		/* GET home page. */
		router.get(
		    '/',
		    function(req, res, next)
		    {
			res.render(
			    'index',
			    {
				title: 'MAC Prov Tool',
				help: 'Tools for manipulating MAC keys, MAC provisionning CAN frames and SHE commands for Key provisionning from log files ',
				accordionTab: 0
			    }
			);
		    }
		);
		
		/*
		 * Log Files functions
		 */
		
		/* GET import_log_file. */
		router.get('/import_log_file', function(req, res, next) {
		    res.render('import_log_file',
			       {
				   title: 'Import a log file',
				   help: 'Import a log file and store it in DB',
				   accordionTab: 0
			       });
		});

		/* POST upload_log_file */
		router.post(
		    '/upload_log_file',
		    async (req, res, next) =>
		    {
			var releve, result;
			try
			{
			    form.parse(
				req,
				(err, fields, files) =>
				{
				    if (err)
				    {
					next(err);
					return;
				    }
				    req.fields = fields;
				    req.files = files;
				    
				    var log_file = req.files.log_file;
				    console.log("Uploaded '" + log_file.originalFilename + "' file to: " + log_file.filepath);
				    fs.readFile(
					log_file.filepath,
					'utf8',
					(err, data) =>
					{
					    // First let's write file in DB repository
					    var targetFilePath = DbLogPath + "/" + log_file.originalFilename;
					    console.log("Target file path: " + targetFilePath);
					    var newTargetFilePath = targetFilePath;
					    var fileCntr = 0;
					    var extension = path.extname(newTargetFilePath);
					    var name = path.basename(newTargetFilePath, extension);
					    while (fs.existsSync(newTargetFilePath))
					    {
						console.log("Target file path exists: " + newTargetFilePath);
						fileCntr++;
						newTargetFilePath =  DbLogPath + "/" + name + '_' + fileCntr + extension;
					    }
					    console.log("Found free target file path : " + newTargetFilePath);
					    fs.rename(
						log_file.filepath,
						newTargetFilePath,
						function (err)
						{
						    if (err)
						    {
							console.log("Couldn't rename file " + log_file.filepath + " !");
							next(err);
							return;
						    }
						    console.log('File Renamed to ' + newTargetFilePath + '!');
						    const importDateRE = /^date (?<date>.*)$/;
						    const uuidRE = /^\/\/ Measurement UUID: (?<uuid>[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})$/;
						    const versionRE = /^\/\/ version (?<version>[0-9.]+)$/;
						    var lines = data.toString().split(/\r?\n/);
						    console.log('File has ' + lines.length + ' lines !');
						    var dateLine = lines.filter(elem => elem.match(importDateRE));
						    console.log("Date line: " + dateLine)
						    var uuidLine = lines.filter(elem => elem.match(uuidRE));
						    console.log("UUID line: " + uuidLine)
						    var versionLine = lines.filter(elem => elem.match(versionRE));
						    console.log("Version line: " + versionLine)
						    var logdate, uuid, version;
						    dateLine.map(
							(line) =>
							{
							    var fields = importDateRE.exec(line);
							    logdate = fields.groups.date;
							    console.log("    Log Date = " + logdate);
							}
						    );
						    uuidLine.map(
							(line) =>
							{
							    var fields = uuidRE.exec(line);
							    uuid = fields.groups.uuid;
							    console.log("    UUID = " + uuid);
							}
						    );
						    versionLine.map(
							(line) =>
							{
							    var fields = versionRE.exec(line);
							    version = fields.groups.version;
							    console.log("    Version = " + version);
							}
						    );
						    keystoredb.run("INSERT INTO LogFiles (Name, LogDate, ImportDate, Version, Size, LinesNb, UUID, Content)   \
                                                                           VALUES        (   ?,       ?,          ?,       ?,    ?,       ?,    ?,       ?);",
								   [path.basename(newTargetFilePath),
								    logdate,
								    (new Date()).toString(),
								    version,
								    log_file.size,
								    lines.length,
								    uuid, 
								    data],
								   (err) =>
								   {
								       if (err)
								       {
									   console.log("Error while adding log file record in DB!");
				 					   next(err);
									   return;
								       }
								       res.render(
									   'upload_log_files',
									   {
									       title: 'Upload a log file',
									       help: 'Upload, process and store a log file and its parameters for further MAC Prov frames extraction',
									       content: 'File ' + log_file.originalFilename + ' uploaded successfully !',
									       accordionTab: 0
									   }
								       );
								   }
								  );
						}
					    );
					}
				    );
				}
			    );
			}
			catch(err)
			{
			    next(err);
			    return;
			}
		    }
		);
		
		/* GET list_log_file. */
		router.get(
		    '/list_log_files',
		    function(req, res, next)
		    {
			var stmt = "SELECT Name, LogDate, Size, FramesExtracted FROM LogFiles";
			keystoredb.all(
			    stmt,
			    [],
			    (err, rows) =>
		            {
		                if (err)
				{
				    next(err);
				    return;
				}
				var contentHtml = "{[";
				var firstRow = true;
				rows.forEach(
				    (row) =>
				    {
					contentHtml +=
					    (firstRow ? "" : "")+
					    "{Name:'"+row.Name+
					    "',LogDate:'"+row.LogDate+
					    "',ImportDate:'"+row.ImportDate+
					    "',Size:"+row.Size+
					    ",UUID:'"+row.UUID+
					    "',FramesExtracted:"+(row.FramesExtracted ? "true" : "false")+
					    "}";
					firstRow = false;
				    }
				);
				contentHtml += "]}";
				res.render(
				    'list_log_files',
				    {
					title: 'List stored log files',
					help: 'List all log files imported and stored locally in DB',
					logfiles: contentHtml,
					accordionTab: 0
				    }
				);
			    }
			);
		    }
		);
		
		/* GET delete_log_files. */
		router.get(
		    '/delete_log_files',
		    function(req, res, next)
		    {
			res.render(
			    'delete_log_files',
			    {
				title: 'Delete stored log files',
				help: 'Delete LOG files stored in DB (record & files)',
				accordionTab: 0
			    }
			);
		    }
		);
		
		/* GET extract_mac_frames. */
		router.get(
		    '/extract_mac_frames',
		    function(req, res, next)
		    {
			res.render(
			    'extract_mac_frames',
			    {
				title: 'Extract MAC Prov. frames',
				help: 'Extract MAC provisionning frames from an uploaded log file',
				accordionTab: 1
			    }
			);
		    }
		);
		
		/* GET list_mac_prov_frame. */
		router.get(
		    '/list_mac_prov_frame',
		    function(req, res, next)
		    {
			res.render(
			    'list_mac_prov_frame',
			    {
				title: 'List stored MAC prov frames',
				help: 'List stored MAC Provisionning frames found in log files',
				accordionTab: 1
			    }
			);
		    }
		);
		
		/* GET list_she_args_packets. */
		router.get('/extract_she_args_packets', function(req, res, next) {
		    res.render('extract_she_args_packets',
			       {
				   title: 'Extract SHE args packets',
				   help: 'Extract SHE args packets from MAC prov frames',
				   accordionTab: 2
			       });
		});
		
		/* GET list_she_args_packets. */
		router.get('/list_she_args_packets', function(req, res, next) {
		    res.render('list_she_args_packets',
			       {
				   title: 'List stored SHE args packets',
				   help: '',
				   accordionTab: 2
			       });
		});
		
		/* GET unwrap_mac_keys. */
		router.get('/unwrap_mac_keys', function(req, res, next) {
		    res.render('unwrap_mac_keys',
			       {
				   title: 'Unwrap MAC keys provided in a selected SHE args packets',
				   help: '',
				   accordionTab: 2
			       });
		});
	    }
	});
	
module.exports = router;
