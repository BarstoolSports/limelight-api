"use strict";

var Q = require("q");
var request = require("request");
var qs = require("qs");
var crypto = require("crypto");

var API = function(config) {
	this.logger = config.logger || {};
	this.logger.error = this.logger.error || function(data) {
		console.error("[Error]", data);
	};
	this.logger.log = this.logger.log || function(data) {
		console.log(data);
	};

	if (!config.host || !config.name || !config.version) {
		this._log("error", "Some URL parameters are missing");
		return;
	}

	if (!config.user || !config.apiKey) {
		this._log("error", "Some credentials are missing");
		return;
	}

	this.user = config.user;
	this.apiKey = config.apiKey;
	this.format = config.format || "json";
	this.debug = config.debug;
	this.dryRun = config.dryRun;
	this.apiBase = (config.protocol || "http") + "://" + config.host + "/" + config.name + "/v" + config.version + "/";
};

API.prototype.request = function(params) {
	var url = this.apiBase + params.endpoint;
	this._log("debug", "API base: " + url);
	var timestamp = (new Date()).getTime();
	var data = {
		"method": params.method || "GET",
		"uri": url,
		"headers": {
			"X-LLNW-Security-Principal": this.user,
			"X-LLNW-Security-Timestamp": timestamp
		}
	}
	if (this.format === "json") {
		data.headers["Content-Type"] = "application/json";
		data.headers["Accept"] = "application/json";
	} else if (this.format === "xml") {
		data.headers["Content-Type"] = "application/xml";
		data.headers["Accept"] = "application/xml";
	}
	if (data.method === "GET") {
		data.qs = params.data || {};
	} else if (data.method === "POST" || data.method === "PUT") {
		data.body = params.data || "";
	}
	data.headers["X-LLNW-Security-Token"] = generateHMAC(url, timestamp, this.apiKey, data);
	var defer = Q.defer();
	if (this.dryRun) {
		defer.resolve(data);
		return defer.promise;
	}
	var req = request(data, (function(error, response, body) {
		if (error) {
			this._log("error", error);
			defer.reject(error);
		} else if (response.statusCode < 200 || response.statusCode >= 300) {
			body = body || response.body;
			if (this.format === "json") {
				body = JSON.parse(body);
			}
			this._log("error", body);
			defer.reject(body);
		} else {
			if (this.format === "json") {
				body = JSON.parse(body);
				this._log("debug", "Response: " + JSON.stringify(body, null, 4));
			} else {
				this._log("debug", "Response: " + body);
			}
			defer.resolve(body);
		}
	}).bind(this));
	this._log("debug", "Request headers: " + JSON.stringify(req.headers, null, 4));
	return defer.promise;
};

API.prototype._log = function(type, message) {
	if (type === "error") {
		this.logger.error(message);
	} else if (type === "debug" && this.debug) {
		this.logger.log(message);
	}
};

function generateHMAC(url, timestamp, apiKey, request) {
	var data = request.method + url;
	if (request.qs) {
		data += qs.stringify(request.qs);
	}
	data += timestamp;
	if (request.body) {
		data += request.body;
	}
	var key = new Buffer(apiKey, "hex");
	return crypto.createHmac("sha256", key).update(data).digest("hex");
};

module.exports = API;
