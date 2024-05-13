Java.perform(function () {
    try {
        hook_media_player()
    } catch (error) {
        console.log(error)
    }
})

function hook_media_player() {
    Java.scheduleOnMainThread(function () {
        const reg_exp = /\d+/g
        let res_id

        const MediaPlayer = Java.use("android.media.MediaPlayer")

        MediaPlayer.setDataSource.overload('android.content.Context', 'android.net.Uri').implementation = function (Context, Uri) {
            const result = this.setDataSource(Context, Uri)
            res_id = Uri.toString().match(reg_exp)
            
            get_resource(res_id)

            return result
        }
    })
}

function get_resource(res_id) {
    const context = get_context()
    const resources = context.getResources()
    const TypedValue = Java.use("android.util.TypedValue")
    
    const typed_value = TypedValue.$new()
    const input_stream = resources.openRawResource(Number(res_id), typed_value)
    save_file(input_stream, res_id)       
}

function save_file(input_stream, fileName) {
    const File = Java.use("java.io.File")

    let file = File.$new("/sdcard/", fileName + ".json")

    const FileOutputStream = Java.use("java.io.FileOutputStream")
    let out = FileOutputStream.$new(file)

    const byteArr = new Array(1024).fill(0)
    const buf = Java.array('byte', byteArr)

    let len

    while((len = input_stream.read(buf)) > 0) {
        out.write(buf, 0, len)
    }

    input_stream.close()
    out.close()
    console.log("Raw file saved successfully.")
}

function get_context() {
    const currentApplication = Java.use('android.app.ActivityThread').currentApplication()
    return currentApplication.getApplicationContext()
}