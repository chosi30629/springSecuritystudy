package me.chosi.demospringsecurityform.common;

import me.chosi.demospringsecurityform.account.Account;
import me.chosi.demospringsecurityform.account.AccountService;
import me.chosi.demospringsecurityform.book.Book;
import me.chosi.demospringsecurityform.book.BookRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class DefaultDataGenerator implements ApplicationRunner {

    @Autowired
    AccountService accountService;

    @Autowired
    BookRepository bookRepository;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        Account seongil = createUser("seongil");
        Account chosi = createUser("chosi");

        createBook("spring", seongil);
        createBook("hibernate", chosi);

    }

    private Book createBook(String title, Account seongil) {
        Book book = new Book();
        book.setTitle(title);
        book.setAuthor(seongil);
        return bookRepository.save(book);
    }

    private Account createUser(String username) {
        Account account = new Account();
        account.setUsername(username);
        account.setPassword("123");
        account.setRole("USER");
        return accountService.createNew(account);
    }

}
