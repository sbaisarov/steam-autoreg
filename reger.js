var SteamUser = require('steam-user');
var request = require('sync-request');
var fs = require('fs');
const SteamCommunity = require('steamcommunity');
const winston = require('winston');

const logger = winston.createLogger({
  level: "debug",
  transports: [
   new winston.transports.File({ filename: 'database/logs.txt' })
  ]
});

let community = new SteamCommunity();
let client = new SteamUser();

function main(totalAmount) {
  community.totalAmount = totalAmount;  // save the reference
  client.logOn();
  client.on('loggedOn', function(details) {
    var amount = 0;
    registrate(amount);
  })
}

function registrate(amount) {
  let username = generateLoginName();
  let password = generateCredential();
  let email = generateCredential() + "@" + generateCredential() + ".com";
  client.createAccount(username, password, email, function(code) {
      if (code == SteamUser.Steam.EResult.OK) {
        logger.info("Account created: " + username);
        amount++;
        writeToDisk(username, password);

        community.login({accountName: username, password: password}, function() {
          community.editProfile({name: username}, (err) => {
            if (err) {
              logger.error(err);
            }
          });
          community.profileSettings({inventory: SteamCommunity.PrivacyState.Public}, (err) => {
            if (err) {
              logger.error(err);
            }
            if (amount == community.totalAmount) setTimeout(process.exit.bind(process), 3000);
          })
          // community.requestValidationEmail((result) => {
          //   if (amount == totalAmount) {
          //     setTimeout(process.exit.bind(process), 3000);
          //   }
          // })
        })
      if (amount < community.totalAmount) setTimeout(registrate, 10000, amount);
    }
      else {
        relog(amount);
      }
    })
}

function relog(amount) {
  client = null;
  client = new SteamUser();
  client.logOn();
  client.on('loggedOn', function(details) {
    logger.debug("LIMIT REACHED!. Waiting 3 seconds to start again...");
    setTimeout(registrate, 3000, amount);
  });
}

function generateCredential() {
  var text = "";
  var possible = "abcdefghijklmnopqrstuvwxyz0123456789";

  var length = 6 + Math.floor(Math.random() * 3);
  for (var i = 0; i < length; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}

function generateLoginName() {
  while (true) {
    loginName = generateCredential();
    var response = request("GET", "https://store.steampowered.com/join/checkavail", {
      qs: {accountname: loginName, count: "1"}
    })
    var resp = JSON.parse(response.getBody());
    if (resp.bAvailable) return loginName;
  }
}

function writeToDisk(username , password) {
  fs.open("accounts.txt", "a", 0644, function(err, file_handle) {
   fs.write(file_handle, username + ":" + password + "\r\n", null, 'ascii', function(err, written) {
   });
  });

  fs.open("database/accounts_temp.txt", "a", 0644, function(err, file_handle) {
   fs.write(file_handle, username + ":" + password + "\r\n", null, 'ascii', function(err, written) {
   });
  });
}

// main(1)
