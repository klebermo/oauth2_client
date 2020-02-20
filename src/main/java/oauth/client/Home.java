package oauth.client;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class Home {
  @RequestMapping("/")
  public String index() {
    return "index";
  }

  @RequestMapping(value="/login", method=RequestMethod.GET)
  public String login(@RequestParam("code") String code) {
    return "redirect:/";
  }
}
