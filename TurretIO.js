/*

Copyright 2014 Loop Science 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/


var http = require('https');
var crypto = require('crypto');

var TurretIO = function TurretIO(key, secret) {

  if (!(this instanceof TurretIO)) {
    return new TurretIO(key, secret);
  }

  this.key = key;
  this.secret = secret;
  this.domain = 'api.turret.io'

  this.version = '0.1a';


  this.newAccountManager = function() {
	return new this.AccountManager(this);
  }

  this.newSegmentManager = function() {
    return new this.SegmentManager(this);
  }

  this.newSegmentEmailManager = function() {
    return new this.SegmentEmailManager(this);
  }

  this.newUserManager = function() {
    return new this.UserManager(this);
  }

  this.getSecret = function() {
    return new Buffer(this.secret, 'base64').toString('binary');
  }

  this.buildStringToSign = function(uri, t, data) {
    if(typeof(data) !== 'undefined'
        && data !== null
        && data !== 'null') {
      return uri+data+t;
    }

    return uri+t;
  }

  this.sign = function(uri, t, data) {
    var hmac = crypto.createHmac('sha512', this.getSecret());
    hmac.write(this.buildStringToSign(uri, t, JSON.stringify(data)))
    hmac.end()

    return hmac.read()
  }

  this.request = function(uri, t, type, data, callback) {
    var headers = {};
    headers['X-LS-Time'] = t
    headers['X-LS-Key'] = this.key;
    headers['X-LS-Auth'] = new Buffer(this.sign(uri, t, data)).toString('base64');
    headers['Content-Type'] = 'text/json; charset=UTF-8';

    var options = {
      hostname: this.domain,
      port: 443,
      path: uri,
      headers: headers
    };

    if(type == 'GET') {
      options['method'] = 'GET';
      this._request(options, callback);
    }

    if(type == 'POST') {
      options['method'] = 'POST';
      this._request(options, callback, JSON.stringify(data))
    }

  }

  this._request = function(options, callback, data) {
    var req = http.request(options, function(res){
      console.log("STATUS:" + res.statusCode);
      res.on('data', function(chunk){
        console.log("BODY:", chunk.toString());
        callback(chunk);
      });

    });

    req.on('error', function(e){
      console.log('Error: ' + e.message);
      console.log(e);
      callback(e);
    });

    if(typeof(data) != 'undefined') {
      req.write(new Buffer(data).toString('base64'));
    }

    req.end();
  }

  this.makeUnixTimestamp = function() {
    return Math.round(new Date().getTime()/1000);
  }

  this.GET = function(uri, callback) {
    var t = this.makeUnixTimestamp();
    this.request(uri, t, 'GET', null, callback);
  }

  this.POST = function(uri, data, callback) {
    var t = this.makeUnixTimestamp();
    this.request(uri, t, 'POST', data, callback);
  }

  this.AccountManager = function(TurretIO) {

    this.uri = '/latest/account';

    this.get = function(callback) {
      TurretIO.GET(this.uri, callback);
    }

    this.set = function(outgoing_method, options, callback) {
      if(outgoing_method == 'turret.io') {
        TurretIO.POST(this.uri+'/me', {'type':outgoing_method}, callback);
      }

      if(outgoing_method == 'aws') {
        if(!'access_key' in options || !'secret_access_key' in options) {
          console.log('AWS credentials needed');
          callback('AWS credentials needed');
        }

        TurretIO.POST(this.uri+'/me', {'type':outgoing_method, 'aws':options}, callback);
      }

      if(outgoing_method == 'smtp') {
        if(!'smtp_host' in options ||
            !'smtp_username' in options ||
            !'smtp_password' in options) {
              console.log('SMTP credentials required');
              callback('SMTP credentials required');
            }

        TurretIO.POST(this.uri+'/me', {'type':outgoing_method, 'smtp':options}, callback);
      }
    }
  }

  this.SegmentManager = function(TurretIO) {

    this.uri = '/latest/segment';

    this.get = function(name, callback) {
      TurretIO.GET(this.uri+'/'+name, callback);
    }

    this.create = function(name, attribute_obj, callback) {
      TurretIO.POST(this.uri+'/'+name, {attributes: attribute_obj}, callback);
    }

    this.update = function(name, attribute_obj, callback) {
      TurretIO.POST(this.uri+'/'+name, {attributes: attribute_obj}, callback);
    }

  }

  this.SegmentEmailManager = function(TurretIO) {

    this.uri = '/latest/segment';

    this.get = function(segment_name, email_id, callback) {
      TurretIO.GET(this.uri+'/'+segment_name+'/email/'+email_id, callback);
    }

    this.create = function(segment_name, subject, html_body, plain_body, callback) {
      TurretIO.POST(this.uri+'/'+segment_name+'/email', {'subject':subject,
            'html':html_body, 'plain':plain_body}, callback);
    }

    this.update = function(segment_name, email_id, subject, html_body, plain_body, callback) {
      TurretIO.POST(this.uri+'/'+segment_name+'/email/'+email_id, {'subject':subject,
            'html':html_body, 'plain':plain_body}, callback);
    }

    this.sendTest = function(segment_name, email_id, email_from, recipient, callback) {
      TurretIO.POST(this.uri+'/'+segment_name+'/email/'+email_id+'/sendTestEmail', {'email_from':email_from,
            'recipient':recipient}, callback);
    }

    this.send = function(segment_name, email_id, email_from, callback) {
      TurretIO.POST(this.uri+'/'+segment_name+'/email/'+email_id+'/sendEmail', {'email_from':email_from},
            callback);
    }
  }

  this.UserManager = function(TurretIO) {

    this.uri = '/latest/user';

    this.get = function(email, callback) {
      TurretIO.GET(this.uri+'/'+email, callback);
    }

    this.set = function(email, attribute_obj, property_obj, callback) {
      if(Object.keys(property_obj).length > 0) {
        attribute_obj['properties'] = property_obj;
      }
  
      TurretIO.POST(this.uri+'/'+email, attribute_obj, callback);
    }
  }

}

module.exports = TurretIO;
