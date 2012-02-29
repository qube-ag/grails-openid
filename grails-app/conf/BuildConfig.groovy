grails.project.dependency.resolution = {
    // inherit Grails' default dependencies
    inherits("global") {
        
    }
    log "error" // log level of Ivy resolver, either 'error', 'warn', 'info', 'debug' or 'verbose'
    checksums true // Whether to verify checksums on resolve

    repositories {
        inherits true // Whether to inherit repository definitions from plugins
    }
    dependencies {
        // specify dependencies here under either 'build', 'compile', 'runtime', 'test' or 'provided' scopes eg.
      
        runtime 'xerces:xercesImpl:2.6.2'
    }
} 
