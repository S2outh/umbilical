use south_common::chell::chell_definition;

#[chell_definition(id = 0, address = south_common::chell)]
mod groundstation {
    mod umbilical {
        #[chv(u32)]
        struct TelecommandCounter;
    }
}
