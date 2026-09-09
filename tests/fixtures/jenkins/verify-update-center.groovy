import hudson.model.DownloadService
import jenkins.model.Jenkins

def site = Jenkins.get().updateCenter.sites.find { it.id == "default" }
assert site != null
println("MIRRORSWITCH_SIGNATURE_CHECK=" + DownloadService.signatureCheck)
def result = site.updateDirectlyNow()
println("MIRRORSWITCH_UPDATE_CENTER_RESULT=" + result.kind + ":" + result.message)
assert result.kind.toString() == "OK"
