#!/usr/bin/env node

/**
 * db.js
 *
 * Express javascript application for DB manip
 */

/**
 * Load Modules Required
 *
 */
// Require FS for passing cert&key for https www server
const fs = require('fs');
// Require path for addressing static public dir for www server
var path = require('path');
// Require morgan as a console/debug logger
var logger = require('morgan');
// Require sqlite3 for accounting (storing/fetching keys)
const sqlite3 = require('sqlite3').verbose();
// Require util for format method
const util = require('util');

// DB file path for storing log files
// const DbFilePath = process.env.HOME + '/AppData/Local/rapr/accounting.db';
// const DbFilePath = process.env.HOME + '/AppData/Local/rapr/accounting.db';
const DbFilePath = process.env.MAC_PROV_ROOT + '/var/lib/keystore.db';

/**
 * Constructor for DB access object
 *
 // The object instance supporting this module
 */
function db()
{
    console.log('****** Constructor for db ...');
    this.dbFilePathName = '';
    this.keystore = '';
    this.params = {};

    /**
     * openDb
     *
     * Function opening the database
     */
    this.openDb = async function()
    {
	console.log('****** Opening MAC Keys DB ...');
	// Instanciate accounting DB
	this.keystore =
	    new sqlite3.Database(
		DbFilePath,
		sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE | sqlite3.OPEN_FULLMUTEX | sqlite3.OPEN_PRIVATECACHE,
		(err) =>
		{
		    if (err)
		    {
			console.error(err.message);
			throw err;
		    }
		    else
			console.log('****** Accounting DB openned !');
		}
	    );
    }

    /**
     * persistAccount
     *
     * Create Account persistent object
     *
     * returns Account id
     */
    this.persistAccount = function()
    {
	console.log('****** db.persistAccount ...');
	var lastId;
	try
	{
	    let stmt = "INSERT INTO Accounts (Iban, BankId, CurrencyId) VALUES (?, ?, ?);";
	    this.keystore.run(
		stmt,
		[this.params.iban, this.params.bankId, this.params.currencyId],
		(err) =>
		{
		    if (err)
			throw err;
		    else
			lastId = this.lastID;
		}
	    );
	}
	catch(err)
	{
	    console.log("[persistAccount] Error: "+err);
	}
	return lastId;
    }

    /**
     * getAccountByIban
     *
     * Get Account persistent object by Iban
     *
     * returns Account object
     */
    this.getAccountByIban = function()
    {
	console.log('****** db.getAccountByIban ...');
	this.result = undefined;
	try
	{
	    let stmt = "SELECT id, Iban, BankId, CurrencyId FROM Accounts WHERE Iban = ?";
	    this.keystore.get(
		stmt,
		[this.params.iban],
		(err, row) =>
		{
		    if (err)
			throw err;
		    this.result = new Object;
		    this.result.id = row.id;
		    this.result.Iban = row.Iban;
		    this.result.BankId = row.BankId;
		    this.result.CurrencyId = row.CurrencyId;
		    console.log("Account:");
		    console.log("    id = "+this.result.id);
		    console.log("    Iban = "+this.result.Iban);
		    console.log("    BankId = "+this.result.BankId);
		    console.log("    CurrencyId = "+this.result.CurrencyId);
		}
	    );
	}
	catch (err)
	{
	    console.log("[getAccountByIban] Error: "+err);
	}
	return this.result;
    }

    /**
     * persistCurrency
     *
     * Create Currency persistent object
     *
     * returns Currency id
     */
    this.persistCurrency = function()
    {
	console.log('****** db.persistCurrency ...');
	var lastId;
	try
	{
	    let stmt = "INSERT INTO Currencies (LongName, Symbol, Code) VALUES (?, ?, ?);";
	    this.keystore.run(
		stmt,
		[this.params.longName, this.params.symbol, this.params.code],
		(err) =>
		{
		    if (err)
			throw err;
		    else
			lastId = this.lastID;
		}
	    );
	}
	catch(err)
	{
	    console.log(err);
	}
	return lastId;
    }

    /**
     * getCurrencyByCode
     *
     * Get Currency by Code
     *
     * returns Currency object
     */
    this.getCurrencyByCode = function(codeParam)
    {
        var code = codeParam || this.params.code;
	console.log('****** db.getCurrencyByCode('+code+') ...');
	this.result = undefined;
	try
	{
	    let stmt = "SELECT id, LongName, Symbol, Code FROM Currencies WHERE Code = ?;";
	    
	    console.log(stmt);
	    this.keystore.get(
		stmt,
		[code],
		(err, row) =>
		{
		    if (err)
			throw err;
		    this.result = new Object;
		    this.result.id = row.id;
		    this.result.LongName = row.LongName;
		    this.result.Symbol = row.Symbol;
		    this.result.Code = row.Code;
		    console.log("Currency:");
		    console.log("    id = "+this.result.id);
		    console.log("    LongName = "+this.result.LongName);
		    console.log("    Symbol = "+this.result.Symbol);
		    console.log("    Code = "+this.result.Code);
		}
	    );
	}
	catch(err)
	{
	    console.log(err);
	}
	return this.result;
    }

    /**
     * getCurrencyBySymbol
     *
     * Get Currency by Symbol
     *
     * returns Currency object
     */
    this.getCurrencyBySymbol = function()
    {
	console.log('****** db.getCurrencyBySymbol('+this.params.symbol+') ...');
	this.result = undefined;
	try
	{
	    let stmt = "SELECT id, LongName, Symbol, Code FROM Currencies WHERE Symbol = ?;";
	    
	    console.log(stmt);
	    this.keystore.get(
		stmt,
		[this.params.symbol],
		(err, row) =>
		{
		    if (err)
			throw err;
		    this.result = new Object;
		    this.result.id = row.id;
		    this.result.LongName = row.LongName;
		    this.result.Symbol = row.Symbol;
		    this.result.Code = row.Code;
		    console.log("Currency:");
		    console.log("    id = "+this.result.id);
		    console.log("    LongName = "+this.result.LongName);
		    console.log("    Symbol = "+this.result.Symbol);
		    console.log("    Code = "+this.result.Code);
		}
	    );
	}
	catch(err)
	{
	    console.log(err);
	}
	return this.result;
    }

    /**
     * persistBank
     *
     * Create Bank persistent object
     *
     * returns Bank id
     */
    this.persistBank = function()
    {
	console.log('****** db.persistBank ...');
	var lastId;
	try
	{
	    let stmt = "INSERT INTO Banks (LongName, Code, Bic) VALUES (?, ?, ?);";
	    this.keystore.run(
		stmt,
		[this.params.longName, this.params.code, this.params.bic],
		(cb => function(err)
		 {
		     return cb(err, this.lastId)
		 }
		) ((err, lastId) =>
		    {
		        console.log("[persistBank] id: "+lastId) // is available
		        if (err)
			    throw err;
		        else {
			    lastId = this.lastID;
			    console.log("[persistBank] id: "+lastId);
		        }
		    })
	    );
	}
	catch(err)
	{
	    console.error(new Error("[persistBank] Error: "+err));
	}
	return lastId;
    }

    this.getBankByBic = () =>
    {
	try
	{
	}
	catch (err)
	{
	    console.log("")
	}
    }

    this.persistBalanceTypeCode = function(db, balanceTypeCodeInstance)
    {
	try
	{
	}
	catch(err)
	{
	    console.log(err);
	}
    }

    this.persistEntry = function(db, entryInstance)
    {
	try
	{
	}
	catch(err)
	{
	    console.log(err);
	}
    }

    this.persistStatusCode = function (db, statusCodeInstance)
    {
	try
	{
	}
	catch(err)
	{
	    console.log(err);
	}
    }
}

// and the module itself
mydb = new db;
module.exports = mydb;
module.exports.openDb = mydb.openDb;
module.exports.persistAccount = mydb.persistAccount;
module.exports.params = {};
module.exports.result = undefined;
