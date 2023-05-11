
// ENCRYPTION GENERATOR
// function createEncryptor(){
    let _this = {};
    /** 
     * @param {String} phrase File Password
     * @param {number} passcode Modulating Code
     * @param {boolean} nolock [optional] 
    */
    function* keyGenerator(phrase, passcode, nolock = false) {
        let last = 0;
        let index = 0;
        if (_this.PRIVATELOCK.length == 0) { nolock = true; }
        let cases = nolock ? 4 : 5;
        while (true) {
            let current = phrase.charCodeAt(index % phrase.length);
            if (index % passcode == 0) {
                switch ((last % cases) + nolock) {
                    case 0:
                        last = (last ^ _this.PRIVATELOCK[(((current ^ index) % _this.PRIVATELOCK.length) + index) % _this.PRIVATELOCK.length]);
                        break;
                    case 1:
                        last = (last + current) % 0xff;
                        break;
                    case 2:
                        last = (Math.floor(last / current));
                        break;
                    case 3:
                        last = (last * current) % 0xff;
                        break;
                    case 4:
                        last = ((last + 0xff) - current) % 0xff;
                        break;
                }
                // last = (last + current) % 0xff;
            } else {
                last = last ^ current;
            }
            index++;
            if(last != 0){
                yield last;
            }
        }
    }
    /**
     * @param {String} phrase Global Password
     * @param {number} code Modulating Code (Randomness)
    */
    function generatePrivateKey(phrase, code) {
        let gen = _this.keyGenerator(phrase, code, true);
        return (",").repeat(0xff).split("").map(a => gen.next().value);
    }
    /** 
     * @param {String} key File Password
     * @param {number} code Modulating Code (Randomness)
     * @param {String} private Global Password
     * @param {number} samples Amount of Sample to check for insecurities 
    */
    function generateStatsFromGeneration(key, code, private, samples = 1E+6) {
        _this.generatePrivateKey(private, code);
        let gen = _this.keyGenerator(key, code);
        let diagram = [];
        for (let i = 1; i < samples; i++) {
            let v = gen.next().value;
            if (diagram[v]) {
                diagram[v].v++;
            } else {
                diagram[v] = { v: 1, c: v };
            }
        }
        diagram = diagram.reduce((p, c) => (p.push(c), p), []);
        return _this.checkInsecure(diagram);
    }
    /** 
     * @param {Array<{v:number,c:byte}>} stats 
     * @returs false if is secure, true otherwise
    */
    function checkInsecure(stats) {
        let max = stats.sort((a, b) => b.v - a.v)[0].v;
        if (stats.length > 10) {
            let check_rep1_threshhold = Math.floor(max * 0.90);
            if (stats.filter(a => a.v >= check_rep1_threshhold).length >= stats.length * 0.2) {
                return true;
            }
            let check_rep2_threshhold = Math.ceil(max * 0.001);
            if (stats.filter(a => a.v <= check_rep2_threshhold).length >= stats.length * 0.6) {
                return true;
            }
            let groups_threshhold = Math.ceil(max * 0.01);
            let groups_count_threshold = 6;
            let currentGroups = [];
            stats.forEach(v => {
                if (currentGroups.length >= groups_count_threshold) {
                    return true; // skip if toomany groups 
                }
                let index = currentGroups.findIndex(a => Math.abs(a.value - v.v) <= groups_threshhold);
                if (currentGroups && (index != -1)) {
                    currentGroups[index].amount++;
                } else {
                    currentGroups.push({ value: v.v, amount: 1 });
                }
            });
            if (currentGroups.length < groups_count_threshold) {
                return true;
            }
        } else {
            return true;
        }

        return false;
    }
    function getRandomCode() {
        let CODEPHRASE = undefined;
        let MAIN_KEYPHRASE = _this.KEYS.PUBLIC;
        let PAIR_KEYPHRASE = _this.KEYS.PRIVATE;
        _this.KEYS
        for(i=30;i>0;i--){
            CODEPHRASE = Math.ceil(Math.random() * MAIN_KEYPHRASE.length * 1.5);
            if(CODEPHRASE==0){continue;}
            if(!generateStatsFromGeneration(PAIR_KEYPHRASE,CODEPHRASE,MAIN_KEYPHRASE,1E+6)){
                break;
            } else {
                _this.debug("// DEBUG! Failed with number :"+CODEPHRASE)
            }
            if(i==1){
                return false;
            }
        }
        _this.KEYS.RANDOMIZER = CODEPHRASE;
        return CODEPHRASE;
    }
    function isReady() {
        return !(!_this.KEYS.PRIVATE?.length||!_this.KEYS.PUBLIC?.length||!_this.KEYS.RANDOMIZER);
    }
    async function runEncryption(progressCallback) {
        if (!_this.isReady()){
            throw new TypeError("Wrong Invocation! Can not invoke encryption with missing arguments!");
        }
        const _read = _this.streams.get.getReader();
        const _write = _this.streams.set.getWriter();
        let accessor = {};
        accessor.read = function() {
            return _read.read();
        }
        accessor.write = function(byte) {
            let data = 0;
            if(Array.isArray(byte)){
                data = new Uint8Array(byte);
            } else {
                data = new Uint8Array([byte]);
            }
            _write.write(data);
        }
        // Original implementation
        let progressCounter = 0;
        _this.generatePrivateKey(_this.KEYS.PUBLIC,_this.KEYS.RANDOMIZER);
        let generator = _this.keyGenerator(_this.KEYS.PRIVATE,_this.KEYS.RANDOMIZER);
        let reader=undefined;
        while(reader=await accessor.read(),reader&&!reader.done) {
            let collector = [];
            for(let value of reader.value){
                let operandByte = generator.next().value;
                collector.push(value^operandByte);
            }
            accessor.write(collector);
            progressCounter += collector.length;
            progressCallback(progressCounter);
        }
        _write.close();
        return true;
    }
    async function doSelectInputFile() {
        let handle = await showOpenFilePicker().then(a=>a).catch(a=>undefined);
        if(!handle){return;}
        let file = await handle[0].getFile();
        let readerStream = file.stream();
        let length = file.size;
        _this.fileInfo = {name:file.name,size:file.size,encrypted:file.name.endsWith("."+_this.ENCRYPTION_SIGNATURE)};
        _this.streams.get=readerStream;
        _this.streams.length=length;
        if(_this.fileInfo.encrypted){
            _this.fileInfo.target=_this.fileInfo.name.split(".").slice(0,-1).join(".");
        } else {
            _this.fileInfo.target=_this.fileInfo.name+"."+_this.ENCRYPTION_SIGNATURE;
        }
    }
    async function doSelectOutputFile() {
        let option = {
            suggestedName:_this.fileInfo.target
        }
        if(!_this.fileInfo.encrypted){option.type=[{description:'EncryptedFile',accept: {'application/octet-stream':['.'+_this.ENCRYPTION_SIGNATURE]}}]}
        let writeHandler = await window.showSaveFilePicker(option).then(a=>a).catch(a=>undefined);
        if(!writeHandler){return;}
        let writerStream = await writeHandler.createWritable();
        _this.streams.set=writerStream;
    }
    _this.debug=console.log;
    _this.PRIVATELOCK = [];
    _this.ENCRYPTION_SIGNATURE = "ncy";
    _this.streams={get:undefined,set:undefined,length:0};
    _this.fileInfo={name:undefined,size:undefined,encrypted:undefined,target:undefined};
    _this.keyGenerator = keyGenerator;
    _this.generatePrivateKey = generatePrivateKey;
    _this.generateStatsFromGeneration = generateStatsFromGeneration;
    _this.checkInsecure = checkInsecure;
    _this.getRandomCode = getRandomCode;
    _this.isReady = isReady;
    _this.doSelectInputFile = doSelectInputFile;
    _this.doSelectOutputFile = doSelectOutputFile;
    _this.runEncryption = runEncryption;
    _this.ENCRYPTION_MODES={UNKNOWN:undefined,ENCRYPT:Symbol("ENCRYPT"),DECRYPT:Symbol("DECRYPT")};
    _this.KEYS = {PRIVATE:undefined, PUBLIC:undefined, RANDOMIZER:undefined, ENCRYPTION_MODE:_this.ENCRYPTION_MODES.UNKNOWN};

    // split contexts
    
    const CALLABLE = (function(){
        return {
            setTarget_Encryption: function(value){if(value){_this.KEYS.ENCRYPTION_MODE=_this.ENCRYPTION_MODES.ENCRYPT}},
            setTarget_Decryption: function(value){if(value){_this.KEYS.ENCRYPTION_MODE=_this.ENCRYPTION_MODES.DECRYPT}},
            setPrivateKey: function(value){_this.KEYS.PRIVATE=value;},
            setPublicKey: function(value){_this.KEYS.PUBLIC=value;},
            setRandomizedKey: function(value){
                if(_this.ENCRYPTION_MODES.DECRYPT==_this.KEYS.ENCRYPTION_MODE){
                    _this.KEYS.RANDOMIZER = value
                }else{
                    throw new Error("Can not set RandomizedKey in non Decrypt mode");
                }
            },
            getRandomizedKey: function(){
                if(undefined===_this.KEYS.RANDOMIZER){
                    if(false==_this.getRandomCode()) {
                        window.alert("Sorry, We could not Generate a secure key from your entered Passwords. Please try again!");
                        throw new EvalError("Could not Generate a secure key from entered Passwords. Aborting...");
                    }
                }
                return _this.KEYS.RANDOMIZER;
            },
            doSelectInputFile: function(){return _this.doSelectInputFile();},
            doSelectOutputFile: function(){return _this.doSelectOutputFile();},
            isInputFileSelected: function(){return _this.streams.get?true:false;},
            isOutputFileSelected: function(){return _this.streams.set?true:false;},
            getLength: function(){return _this.streams.length;},
            isReadyToEncrypt: function(){return _this.isReady();},
            isEncrypted: function(){return _this.isEncrypted();},
            runEncryption: function(progressCallback){
                return _this.runEncryption(progressCallback);
            },
        } 
    })()

    // worker specific methods
    
    onmessage = function (eventMessage) {
        let result = undefined;
        let qID = eventMessage.data.qID;
        if(eventMessage.data.type === "call") {
            result = CALLABLE[eventMessage.data.name]?.call(null, ...eventMessage.data.args);
        // } else if (eventMessage.data.type){
            console.log("Ran Command: " + eventMessage.data.name);
        }

        postMessage({return:result,qID:qID});
    }
// }