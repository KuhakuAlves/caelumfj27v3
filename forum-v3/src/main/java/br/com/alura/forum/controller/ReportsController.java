package br.com.alura.forum.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import br.com.alura.forum.model.OpenTopicByCategory;
import br.com.alura.forum.repository.OpenTopicByCategoryRepository;

@Controller
@RequestMapping("/admin/reports")
public class ReportsController {

	@Autowired
	private OpenTopicByCategoryRepository openTopicRepository;
	
	@GetMapping("/open-topics-by-category")
	public String showOpenTopicCat(Model model) {
		List<OpenTopicByCategory> openTopics = openTopicRepository.findAllByCurrentMonth();
		model.addAttribute("openTopics", openTopics);
		return "report";
	}
}
