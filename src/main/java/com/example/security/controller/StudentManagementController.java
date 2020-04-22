package com.example.security.controller;

import com.example.security.model.Student;
import org.springframework.http.converter.json.GsonBuilderUtils;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.w3c.dom.ls.LSOutput;

import javax.crypto.spec.PSource;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> Students = Arrays.asList(
            new Student(1, "James Bond xxx"),
            new Student(2, "Maria Jones"),
            new Student(3, "Anaa Smith")
    );

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMIN_TRAINEE')")
    public List<Student> getAllStudents(){
        return Students;
    }

    @PostMapping
    //@PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    @PreAuthorize("hasAnyAuthority('student:write')")
    public String registerNewStudent(@RequestBody Student student){
        System.out.println("registerNewStudent");
        System.out.println(student);
        return "registerNewStudent "+student.getName();
    }

    @DeleteMapping(path = "{id}")
    //@PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    @PreAuthorize("hasAnyAuthority('student:write')")
    public String deleteStudent(@PathVariable("id") Integer id){
        System.out.println("deleteStudent");
        System.out.println("student id: "+id);
        return "deleteStudent "+id;
    }


    @PutMapping(path = "{id}")
    //@PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    @PreAuthorize("hasAnyAuthority('student:write')")
    public String updateStudent(@PathVariable("id") Integer id, @RequestBody Student student){
        System.out.println("updateStudent");
        System.out.println(String.format("%s %s", id, student));
        return "updateStudent "+student.getName();
    }

}
