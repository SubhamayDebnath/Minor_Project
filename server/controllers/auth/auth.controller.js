/*
    Register
*/ 
const register = async (req, res, next) => {
  try {
    const { username,phone, email, password } = req.body;
    if (!username || !phone || !email || !password) {
      req.flash("error_msg", "Please fill in all fields");
      return res.redirect("/register");
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      req.flash("error_msg", "Email already in use");
      return res.redirect("/register");
    }
    const hashPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      username,
      phone,
      email,
      password: hashPassword,
    });
    if (!user) {
      req.flash("error_msg", "Failed to create user");
      return res.redirect("/register");
    }
    await user.save();
    res.redirect("/activation");
  } catch (error) {
    console.log(`Login error : ${error}`);
    res.redirect("/error");
  }
};
