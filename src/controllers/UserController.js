const User = require("../models/User");

class UserController {
  create(req, res) {
    return res.render("user/register");
  }

  createUpdate(req, res) {
    return res.render("user/updateuser");
  }

  async index(req, res) {
    const users = await User.paginate();
    return res.render("user/list", { users: users.docs });
  }

  async store(req, res) {
    try {
      const { name, email, password, role } = req.body;

      // Verifica se o e-mail já está cadastrado
      const userExists = await User.findOne({ email });
      if (userExists) {
        return res.status(400).json({ message: "E-mail já cadastrado" });
      }

      // Se um usuário comum tentar criar um admin, bloqueamos
      if (req.user.role !== "admin" && role === "admin") {
        return res.status(403).json({ message: "Ação não permitida" });
      }

      // Cria o usuário (a senha será automaticamente criptografada pelo model)
      const user = await User.create({ name, email, password, role });

      return res.redirect("/");
    } catch (error) {
      return res.status(500).json({ message: "Erro ao criar usuário", error: error.message });
    }
  }

  async edit(req, res) {
    const { id } = req.params;
    const user = await User.findById(id);
    return res.render("user/update", { user: user });
  }

  async update(req, res) {
    try {
      const { id } = req.params;
      const { name, email, password, role } = req.body;

      // Impede que usuários comuns alterem o `role`
      if (req.user.role !== "admin" && role) {
        return res.status(403).json({ message: "Você não pode alterar a permissão de um usuário" });
      }

      // Verifica se o novo e-mail já está cadastrado por outro usuário
      const existingUser = await User.findOne({ email });
      if (existingUser && existingUser._id.toString() !== id) {
        return res.status(400).json({ message: "Este e-mail já está em uso por outro usuário" });
      }

      // Atualiza usuário (criptografa a senha novamente, se fornecida)
      const updatedUser = await User.findByIdAndUpdate(
        id,
        { name, email, password: password ? await bcrypt.hash(password, 4) : undefined, role },
        { new: true }
      );

      return res.redirect("/userslist");
    } catch (error) {
      return res.status(500).json({ message: "Erro ao atualizar usuário", error: error.message });
    }
  }

  async destroy(req, res) {
    try {
      const { id } = req.params;

      // Bloqueia a exclusão de si mesmo (evita um admin deletar sua própria conta por engano)
      if (req.user.id === id) {
        return res.status(403).json({ message: "Você não pode excluir a própria conta" });
      }

      await User.findByIdAndRemove(id);
      return res.redirect("/userslist");
    } catch (error) {
      return res.status(500).json({ message: "Erro ao excluir usuário", error: error.message });
    }
  }
}

module.exports = new UserController();
