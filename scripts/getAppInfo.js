Java.perform(() => {
    get_app_info()
})

function get_app_info() {
    const context = get_context()
    const pm = context.getPackageManager()
    const pInfo = pm.getPackageInfo(context.getPackageName(), 0)
    const appInfo = pm.getApplicationInfo(context.getPackageName(), 0)
    const apk = appInfo.publicSourceDir.value
    const version = pInfo.versionName.value
    
    console.log(`apk path: ${apk}\npackage: ${context.getPackageName()}\nversion: ${version}`)
}

function get_context() {
    const currentApplication = Java.use('android.app.ActivityThread').currentApplication()
    return currentApplication.getApplicationContext()
}