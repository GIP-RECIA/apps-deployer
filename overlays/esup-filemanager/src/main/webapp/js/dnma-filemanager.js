export function raiseEventActif(){
    raiseEvent("ACTIF")
}

export function raiseEventPassif(){
    raiseEvent("PASSIF")
}

export function raiseEventUpload(){
    raiseEvent("UPLOAD")
}

export function raiseEventDownload(){
    raiseEvent("DOWNLOAD")
}

function raiseEvent(tag){
    console.log("DNMA RAISE EVENT", tag)
    const openEvent = new CustomEvent('DNMA-FILE-MANAGER', { detail: { fname: "FNAME-HERE", VALUE: tag } })
    document.dispatchEvent(openEvent)
}