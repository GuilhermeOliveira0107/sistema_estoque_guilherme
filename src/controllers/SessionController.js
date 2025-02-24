const jwt = require("jsonwebtoken");
const User = require("../models/User");

require("dotenv").config();

class SessionController {
  loginForm(req, res) {
    return res.render("login/index");
  }

  logout(req, res) {
    req.session.destroy();
    res.clearCookie("token"); // Remover token ao sair
    return res.redirect("/login");
  }

  async store(req, res) {
    try {
      const { email, password } = req.body;

      const user = await User.findOne({ email });

      if (!user) {
        return res.render("login/index", {
          user: req.body,
          error: "Usuário não encontrado!",
        });
      }

      if (!(await user.compareHash(password))) {
        return res.render("login/index", {
          user: req.body,
          error: "Senha incorreta.",
        });
      }

      console.log("Usuário autenticado:", user);

      // Gerar token JWT
      const token = jwt.sign(
        { id: user._id.toString(), role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || "1h" }
      );

      if (req.headers.accept && req.headers.accept.includes("application/json")) {
        return res.json({ token });
      }

      // Se vier do navegador, salva o token em um cookie e redireciona
      res.cookie("token", token, { 
        httpOnly: true, 
        secure: false,
        sameSite: "lax",
        maxAge: 3600000
      }); // 1 hora

      console.log("Token salvo no cookie:", token); 
      return res.redirect("/");
    } catch (error) {
      return res.status(500).json({ message: "Erro no servidor", error: error.message });
    }
  }
  
}

module.exports = new SessionController();

