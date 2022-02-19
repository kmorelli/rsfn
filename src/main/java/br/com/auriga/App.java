package br.com.auriga;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;

/**
 * Pequeno executavel para realizar operacoes de cifra e decifra 
 * com arquivos RSFN
 * Para ajuda, execute o comando "rsfn"
 */
public class App 
{
    public static void main( String[] args )    
    {
        //Adiciona os parametros previstos
        Options options = new Options();
        for (Parametro parm : Parametro.values()) {
            options.addOption(parm.getOption());
        }

        HelpFormatter formatter = new HelpFormatter();
        
        if (args.length == 0) {
            formatter.printHelp("rsfn", options, true);
            return;            
        }
        
        try {
            CommandLineParser cmdParser = new DefaultParser();
            CommandLine cmd = cmdParser.parse(options, args);
            RSFNApp rsfnApp = new RSFNApp(cmd);
            rsfnApp.inicia();
        } catch (Exception e) {
            e.printStackTrace();
            formatter.printHelp("rsfn", options, true);
        }
    }
}
