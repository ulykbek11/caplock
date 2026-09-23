console.log("CapLock synthetic demo");
console.log("Without CapLock: suspicious fixture could read FAKE_PROJECT_SECRET.");
console.log("With CapLock: Linux Bubblewrap omits project .env from the mount namespace.");
console.log("Run npm run verify:linux in WSL2 to validate the enforcement backend.");
