package br.com.alura.forum.service.infra;

import javax.mail.internet.MimeMessage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import br.com.alura.forum.infra.NewReplyMailFactory;
import br.com.alura.forum.model.Answer;
import br.com.alura.forum.model.topic.domain.Topic;

@Service
public class ForumMailService {

	private static final Logger logger = LoggerFactory.getLogger(ForumMailService.class);
	
	@Autowired
	private JavaMailSender mailSender;
	
	@Autowired
	private NewReplyMailFactory newReplyMailFactory;
	
	@Async
	public void sendNewReplyMailAsync(Answer answer) {
		
		Topic answeredTopic = answer.getTopic();
		
		MimeMessagePreparator messagePreparator = (mimeMessage) -> {
			MimeMessageHelper messageHelper = new MimeMessageHelper(mimeMessage);
			
			messageHelper.setTo(answeredTopic.getOwnerEmail());
			messageHelper.setSubject("Novo comentário em: " + answeredTopic.getShortDescription());
			String messageContent = this.newReplyMailFactory
					.generateNewReplyMailContent(answer);
			messageHelper.setText(messageContent, true);
		};
		
		/*SimpleMailMessage message = new SimpleMailMessage();
		message.setTo(answeredTopic.getOwnerEmail());
		message.setSubject("Novo comentário em: " + answeredTopic.getShortDescription());
		
		message.setText("Olá " + answeredTopic.getOwnerName() + "\n\n" 
				+ "Há uma nova mensagem no fórum! " + answer.getOwnerName() +
				" comentou no tópico: " + answeredTopic.getShortDescription());*/
		
		try {
			mailSender.send(messagePreparator);
		}catch(MailException e) {
			logger.error("Não foi possivel enviar email para " + answer.getTopic().getOwnerEmail() + " - " + e.getMessage());
		}
	}
}
