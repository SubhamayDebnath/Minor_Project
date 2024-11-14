const registerPage = async (req, res) => {
    try {
      res.render("index");
    } catch (error) {
      return res.status(500).json({
        message: "something went wrong",
      });
    }
  };
  
  export { registerPage };