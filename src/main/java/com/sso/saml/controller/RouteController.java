package com.sso.saml.controller;


import com.sso.saml.saml.SAMLUser;
import com.sso.saml.saml.SAMLUserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
public class RouteController {

//    @Autowired
//    private AuthenticationManager authenticationManager;

//    @Autowired
//    private MetadataManager metadataManager;

    //    @Value("${config.contextPath}")
    private String contextPath = "";


    @RequestMapping("/home")
    public ModelAndView home(@SAMLUser SAMLUserDetails user, HttpServletResponse response) throws IOException {
        ModelAndView homeView = new ModelAndView("home");
        homeView.addObject("userId", user.getUsername());
        homeView.addObject("samlAttributes", user.getAttributes());
//        response.setHeader("token","214cbcf1ce5a451b980720c242554b56");
//        response.setHeader("token", "Bearer " + createJwtToken(user));
//        response.sendRedirect(contextPath + "/home.html");
        return homeView;
    }

//    @RequestMapping("/home")
//    public void home(@SAMLUser SAMLUserDetails user, HttpServletRequest request, HttpServletResponse response) throws IOException {
////        ModelAndView homeView = new ModelAndView("home");
////        homeView.addObject("userId", user.getUsername());
////        homeView.addObject("samlAttributes", user.getAttributes());
//        System.out.println("获取用户信息为：" + user.getUsername());
//        response.sendRedirect("/#/ssologin");
//    }


//    private String createJwtToken(SAMLUserDetails user) {
//        UsernamePasswordAuthenticationToken upToken = new UsernamePasswordAuthenticationToken(user.getAttribute("login_name"), user.getPassword());
//        Authentication authentication = authenticationManager.authenticate(upToken);
//        SecurityContextHolder.getContext().setAuthentication(authentication);
////        return JwtTokenUtil.generateToken(user);
//        return null;
//    }

//    @RequestMapping("/idpselection")
//    public ModelAndView idpSelection(HttpServletRequest request) {
//        if (comesFromDiscoveryFilter(request)) {
//            ModelAndView idpSelection = new ModelAndView("idpselection");
//            idpSelection.addObject(SAMLDiscovery.RETURN_URL, request.getAttribute(SAMLDiscovery.RETURN_URL));
//            idpSelection.addObject(SAMLDiscovery.RETURN_PARAM, request.getAttribute(SAMLDiscovery.RETURN_PARAM));
//            Map<String, String> idpNameAliasMap = metadataManager.getIDPEntityNames().stream()
//                    .collect(toMap(identity(), this::getAlias));
//            idpSelection.addObject("idpNameAliasMap", idpNameAliasMap);
//            return idpSelection;
//        }
//        throw new AuthenticationServiceException("SP Discovery flow not detected");
//    }
//
//    private String getAlias(String entityId) {
//        try {
//            return metadataManager.getExtendedMetadata(entityId).getAlias();
//        } catch (MetadataProviderException e) {
//            throw new IllegalStateException("Fail to get alias by entityId " + entityId, e);
//        }
//    }
//
//    private boolean comesFromDiscoveryFilter(HttpServletRequest request) {
//        return request.getAttribute(SAMLConstants.LOCAL_ENTITY_ID) != null &&
//                request.getAttribute(SAMLDiscovery.RETURN_URL) != null &&
//                request.getAttribute(SAMLDiscovery.RETURN_PARAM) != null;
//    }

}
